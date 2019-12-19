#!/bin/bash

# allow coverage to include provider dirs when running integration tests
cp codecov-integ.yml codecov.yml

if git diff origin/master --name-only | grep -qE '(cloudsync/provider.py|cloudsync/providers/|test_provider)'; then
    pytest --cov=cloudsync --cov-report=xml --cov-config=.coveragerc-integ --durations=0 -n=4 cloudsync/tests/test_provider.py --provider "$1" --timeout=600
else
    echo "Skipping integration test because no provider.py|providers/ changes"
fi
