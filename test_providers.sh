#!/bin/bash

if git diff origin/master --name-only | grep -qE '(cloudsync/provider.py|cloudsync/providers/|test_provider)'; then
    pytest --durations=0 -n=4 cloudsync/tests/test_provider.py -k "$1"
else
    echo "Skipping integration tesst because no provider.py|providers/ changes"
fi
