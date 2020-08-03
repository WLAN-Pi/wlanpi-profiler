#!/usr/bin/env bash

RED='\033[0;31m' # red color
NC='\033[0m'     # no color
BOLD=$(tput bold)
NORMAL=$(tput sgr0)


which_profiler=$(which profiler)

if [[ $which_profiler == *"/profiler"* ]]; then
    echo "profiler found"
else
    echo "${BOLD}could not find 'profiler' in 'which profiler' output!!!"
    echo -e "${RED}TEST FAILED${NC}"
    exit 1
fi
