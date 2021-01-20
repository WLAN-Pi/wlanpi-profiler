#!/usr/bin/env bash

set -x

mypy profiler2
black profiler2 --check
isort --check-only profiler2
flake8