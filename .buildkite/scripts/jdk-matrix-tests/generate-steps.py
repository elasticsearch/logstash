from dataclasses import dataclass
import os
import sys
import typing

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString


@dataclass
class BuildkiteEmojis:
  running: str = ":bk-status-running:"
  success: str = ":bk-status-passed:"
  failed: str = ":bk-status-failed:"

def slugify_bk_key(key: str) -> str:
    """
    Convert and return key to an acceptable format for Buildkite's key: field
    Only alphanumerics, dashes and underscores are allowed.
    """

    mapping_table = str.maketrans({'.': '_', ' ': '_', '/': '_'})

    return key.translate(mapping_table)

def get_bk_metadata(key: str) -> typing.List[str]:
    try:
      return os.environ[key].split()
    except KeyError:
        print(f"Missing environment variable [{key}]. This should be set before calling this script using buildkite-agent meta-data get. Exiting.")
        exit(1)

def bk_annotate(job_name_human: str, job_name_slug: str, os: str, jdk: str, status: str, context: str, mode: str) -> str:
  cmd = f"""buildkite-agent annotate "{status} **{job_name_human}** / **{os}** / **{jdk}**" --context={context}"""
  if mode:
     cmd += f" --{mode}"

  return cmd


class WindowsJobs:
    def __init__(self, os: str, jdk: str, group_key: str):
      self.os = os
      self.jdk = jdk
      self.group_key: str

    def all_jobs(self) -> list[typing.Callable[[], typing.Tuple[str, str]]]:
        return [
          self.unit_tests,
        ]

    def unit_tests(self) -> typing.Tuple[str, str]:
        job_name_human = "Java Unit Test"
        job_name_slug = "java-unit-test"
        test_command = "# TODO"

        return job_name_human, test_command
      

class LinuxJobs:
    def __init__(self, os: str, jdk: str, group_key: str):
      self.os = os
      self.jdk = jdk
      self.group_key = group_key

    def all_jobs(self) -> list[typing.Callable[[], typing.Tuple[str, str]]]:
        return [
            self.java_unit_test,
            self.ruby_unit_test,
            self.integration_tests_part_1,
            self.integration_tests_part_2,
            self.pq_integration_tests_part_1,
            self.pq_integration_tests_part_2,
            self.x_pack_unit_tests,
            self.x_pack_integration,
        ]

    def prepare_shell(self) -> str:
        jdk_dir = f"/opt/buildkite-agent/.java/{self.jdk}"
        return f"""#!/usr/bin/env bash
set -euo pipefail

# unset generic JAVA_HOME
unset JAVA_HOME

# LS env vars for JDK matrix tests
export BUILD_JAVA_HOME={jdk_dir}
export RUNTIME_JAVA_HOME={jdk_dir}
export LS_JAVA_HOME={jdk_dir}

export PATH="/opt/buildkite-agent/.rbenv/bin:/opt/buildkite-agent/.pyenv/bin:$PATH"
eval "$(rbenv init -)"
"""

    def emit_command(self, job_name_human, job_name_slug, test_command: str) -> str:
      return LiteralScalarString(f"""
{self.prepare_shell()}
# temporarily disable immediate failure on errors, so that we can update the BK annotation
set +eo pipefail
{test_command}
if [[ $$? -ne 0 ]]; then
  {bk_annotate(job_name_human, job_name_slug, self.os, self.jdk, BuildkiteEmojis.failed, context=self.group_key, mode="append")}
  exit 1
else
  {bk_annotate(job_name_human, job_name_slug, self.os, self.jdk, BuildkiteEmojis.success, context=self.group_key, mode="append")}
fi
      """)

    def java_unit_test(self) -> typing.Tuple[str, str]:
        job_name_human = "Java Unit Test"
        job_name_slug = "java-unit-test"
        test_command = '''
export ENABLE_SONARQUBE="false"
ci/unit_tests.sh java
        '''

        return job_name_human, self.emit_command(job_name_human, job_name_slug, test_command)

    def ruby_unit_test(self) -> typing.Tuple[str, str]:
        job_name_human = "Ruby Unit Test"
        job_name_slug = "ruby-unit-test"
        test_command = """
ci/unit_tests.sh ruby
        """

        return job_name_human, self.emit_command(job_name_human, job_name_slug, test_command)

    def integration_tests_part_1(self) -> typing.Tuple[str, str]:
        return self.integration_tests(part=1)

    def integration_tests_part_2(self) -> typing.Tuple[str, str]:
        return self.integration_tests(part=2)

    def integration_tests(self, part: int) -> typing.Tuple[str, str]:
        job_name_human = f"Integration Tests - {part}"
        job_name_slug = f"integration-tests-pt-{part}"
        test_command = f"""
ci/integration_tests.sh split {part-1}
        """

        return job_name_human, self.emit_command(job_name_human, job_name_slug, test_command)

    def pq_integration_tests_part_1(self) -> typing.Tuple[str, str]:
        return self.pq_integration_tests(part=1)

    def pq_integration_tests_part_2(self) -> typing.Tuple[str, str]:
        return self.pq_integration_tests(part=2)

    def pq_integration_tests(self, part: int) -> typing.Tuple[str, str]:
        job_name_human = f"IT Persistent Queues - {part}"
        job_name_slug = f"it-persistent-queues-pt-{part}"
        test_command = f"""
export FEATURE_FLAG=persistent_queues
ci/integration_tests.sh split {part-1}
        """

        return job_name_human, self.emit_command(job_name_human, job_name_slug, test_command)

    def x_pack_unit_tests(self) -> typing.Tuple[str, str]:
        job_name_human = "x-pack unit tests"
        job_name_slug = "x-pack-unit-tests"
        test_command = """
x-pack/ci/unit_tests.sh
        """

        return job_name_human, self.emit_command(job_name_human, job_name_slug, test_command)

    def x_pack_integration(self) -> typing.Tuple[str, str]:
        job_name_human = "x-pack integration"
        job_name_slug = "x-pack-integration"
        test_command = """
x-pack/ci/integration_tests.sh
        """

        return job_name_human, self.emit_command(job_name_human, job_name_slug, test_command)


if __name__ == "__main__":
    matrix_oses = get_bk_metadata(key="MATRIX_OSES")
    matrix_jdkes = get_bk_metadata(key="MATRIX_JDKS")

    pipeline_name = os.environ.get("BUILDKITE_PIPELINE_NAME", "").lower()

    structure = {"steps": []}


    for matrix_os in matrix_oses:
        for matrix_jdk in matrix_jdkes:
          group_name = f"{matrix_os}/{matrix_jdk}"
          group_key = slugify_bk_key(group_name)

          if "windows" in pipeline_name:
            jobs = WindowsJobs(os=matrix_os, jdk=matrix_jdk, group_key=group_key)
          else:
            jobs = LinuxJobs(os=matrix_os, jdk=matrix_jdk, group_key=group_key)

          group_steps = []
          for job in jobs.all_jobs():
            job_name_human, shell_command = job()

            step = {
              "label": f"{matrix_os} / {matrix_jdk} / {job_name_human}",
              "agents": {
                  "provider": "gcp",
                  "imageProject": "elastic-images-qa",
                  "image": f"family/platform-ingest-logstash-multi-jdk-{matrix_os}",
                  "machineType": "n2-standard-4",
                  "diskSizeGb": 200,
                  "diskType": "pd-ssd",
                },
                "command": shell_command,
            }

            group_steps.append(step)


          structure["steps"].append({
            "group": group_name,
            "key": slugify_bk_key(group_name),
            "steps": group_steps})


    YAML().dump(structure, sys.stdout)
