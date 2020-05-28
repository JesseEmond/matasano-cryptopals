#!/bin/bash

# Executes all the python files in the project. This is used as a convenience
# rather than using unittest (challenges are just standalone programs with
# asserts). If any of the program returns a non-zero exit code, this exits with
# a non-zero exit code.

# Exit if any test fails.
set -e

function run_test {
  prefix=$1
  file=$2
  module=$prefix.$(basename $file .py)
  echo "Running $module..."
  python -m $module
}

for file in src/*.py; do
  run_test src $file
done

for set in src/set_*; do
    set=$(basename $set)
    for file in src/$set/*.py; do
        run_test src.$set $file
    done
done
