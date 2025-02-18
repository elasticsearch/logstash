#!/usr/bin/env sh

cd "$( dirname "$0" )"
find . -name '*.gemspec' | xargs -n1 gem build