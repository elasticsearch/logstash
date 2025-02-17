#!/bin/bash

# This should be called from top repository folder.
# It runs the `rake artifact:all` command in a docker image that has the required
# dependencies.
#
# The artifacts will be placed in the build/ folder.

docker build -f rakelib/Dockerfile.artifacts -t ls-artifacts rakelib/
docker run --rm \
	-v $(pwd):/logstash:delegated \
	ls-artifacts \
	sh -c "cd logstash && rake artifact:all"
