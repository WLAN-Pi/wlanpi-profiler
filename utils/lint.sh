#!/usr/bin/env bash

set -x

mypy profiler
black profiler --check
isort --check-only profiler
flake8 profiler