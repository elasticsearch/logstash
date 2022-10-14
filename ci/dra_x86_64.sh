#!/bin/bash -ie
#Note - ensure that the -e flag is set to properly set the $? status if any command fails
echo "####################################################################"
echo "##################### Starting $0"
echo "####################################################################"

source ./dra_common.sh

# WORKFLOW_TYPE is a CI externally configured environment variable that could assume "snapshot" or "staging" values
case "$WORKFLOW_TYPE" in
    snapshot)
        info "Building artifacts for the $WORKFLOW_TYPE workflow..."
        if [ -z "$VERSION_QUALIFIER_OPT" ]; then
            rake artifact:all
        else
            # Qualifier is passed from CI as optional field and specify the version postfix
            # in case of alpha or beta releases:
            # e.g: 8.0.0-alpha1
            VERSION_QUALIFIER="$VERSION_QUALIFIER_OPT" rake artifact:all
            STACK_VERSION="${STACK_VERSION}-${VERSION_QUALIFIER_OPT}"
        fi
        STACK_VERSION=${STACK_VERSION}-SNAPSHOT
        info "Build complete, setting STACK_VERSION to $STACK_VERSION."
        ;;
    staging)
        info "Building artifacts for the $WORKFLOW_TYPE workflow..."
        if [ -z "$VERSION_QUALIFIER_OPT" ]; then
            RELEASE=1 rake artifact:all
        else
            # Qualifier is passed from CI as optional field and specify the version postfix
            # in case of alpha or beta releases:
            # e.g: 8.0.0-alpha1
            VERSION_QUALIFIER="$VERSION_QUALIFIER_OPT" RELEASE=1 rake artifact:all
            STACK_VERSION="${STACK_VERSION}-${VERSION_QUALIFIER_OPT}"
        fi
        info "Build complete, setting STACK_VERSION to $STACK_VERSION."
        ;;
    *)
        error "Workflow (WORKFLOW_TYPE variable) is not set, exiting..."
        ;;
esac

info "Saving tar.gz for docker images"
docker save docker.elastic.co/logstash/logstash:${STACK_VERSION} | gzip -c > build/logstash-${STACK_VERSION}-docker-image-x86_64.tar.gz
docker save docker.elastic.co/logstash/logstash-oss:${STACK_VERSION} | gzip -c > build/logstash-oss-${STACK_VERSION}-docker-image-x86_64.tar.gz
docker save docker.elastic.co/logstash/logstash-ubi8:${STACK_VERSION} | gzip -c > build/logstash-ubi8-${STACK_VERSION}-docker-image-x86_64.tar.gz

info "GENERATED ARTIFACTS"
for file in build/logstash-*; do shasum $file;done

info "Creating dependencies report for ${STACK_VERSION}"
mkdir -p build/distributions/dependencies-reports/
bin/dependencies-report --csv=build/distributions/dependencies-reports/logstash-${STACK_VERSION}.csv

info "GENERATED DEPENDENCIES REPORT"
shasum build/distributions/dependencies-reports/logstash-${STACK_VERSION}.csv

info "UPLOADING TO INTERMEDIATE BUCKET"
for file in build/logstash-*; do
  gsutil cp $file gs://logstash-ci-artifacts/dra/${STACK_VERSION}/
done

gsutil cp build/distributions/dependencies-reports/logstash-${STACK_VERSION}.csv gs://logstash-ci-artifacts/dra/${STACK_VERSION}/
gsutil cp build/logstash-${STACK_VERSION}-docker-image-x86_64.tar.gz gs://logstash-ci-artifacts/dra/${STACK_VERSION}/
gsutil cp build/logstash-oss-${STACK_VERSION}-docker-image-x86_64.tar.gz gs://logstash-ci-artifacts/dra/${STACK_VERSION}/
gsutil cp build/logstash-ubi8-${STACK_VERSION}-docker-image-x86_64.tar.gz gs://logstash-ci-artifacts/dra/${STACK_VERSION}/

echo "####################################################################"
echo "##################### Finishing $0"
echo "####################################################################"
