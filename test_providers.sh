#!/bin/bash

if git diff origin/master --name-only | grep -qE '(cloudsync/provider.py|cloudsync/providers/)'; then
    pytest --durations=0 -n=2 cloudsync/tests/test_provider.py -k "gdrive or dropbox"
else
    echo "Skipping integration tesst because no provider.py|providers/ changes"
fi
