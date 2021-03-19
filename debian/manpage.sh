#!/bin/sh
echo >&2 "Generating man page using pandoc"
pandoc -s -f markdown-smart -t man wlanpi-profiler.1.md -o wlanpi-profiler.1 || exit
echo >&2 "Done. You can read it with:   man ./wlanpi-profiler.1"