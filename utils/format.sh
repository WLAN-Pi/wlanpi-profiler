#!/usr/bin/env bash

set -x

autoflake --remove-all-unused-imports --recursive --remove-unused-variables --in-place profiler2 --exclude=__init__.py
black profiler2
isort profiler2