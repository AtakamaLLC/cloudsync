#!/bin/bash

if git diff origin/master --name-only | grep -qE 'cloudsync/.*\.py'; then
    if git diff -U0 origin/master | grep -q __version__; then
        echo "OK, version changed"
    else
        echo "FAIL: please increment version"
        exit 1
    fi
else
    echo "Skipping version test because no py files changed"
fi
