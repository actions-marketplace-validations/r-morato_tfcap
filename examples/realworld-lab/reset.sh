#!/bin/sh
# Deletes the lab folder created by setup.sh. Nothing else.
cd "$(dirname "$0")" && rm -rf lab && echo "lab/ removed."
