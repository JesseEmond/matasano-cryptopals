#!/bin/bash

# Executes all the python files in the project. This is used as a convenience
# rather than using unittest (challenges are just standalone programs with
# asserts). If any of the program returns a non-zero exit code, this exits with
# a non-zero exit code.

for file in src/*.py; do
  echo "Running $file..."
  python $file
  ret=$?
  if [[ $ret != 0 ]]; then
    exit $ret
  fi
done
