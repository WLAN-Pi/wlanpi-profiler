#!/usr/bin/env bash

set -x

autoflake --remove-all-unused-imports --recursive --remove-unused-variables --in-place profiler --exclude=__init__.py
black profiler 
isort profiler