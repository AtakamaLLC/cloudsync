#!/bin/bash

set -o errexit

pip install pytest pytest-azurepipelines

pytest --durations=1 --cov=cloudsync --cov-report=xml cloudsync/tests cloudsync/oauth/apiserver.py --timeout=300 &
pid1=$!

pytest --durations=1 --cov=cloudsync --cov-append --cov-report=xml cloudsync/tests/test_provider.py --provider=filesystem &
pid2=$!

echo Waiting for "cloudsync/tests cloudsync/oauth/apiserver.py"
wait $pid1

echo Waiting for "cloudsync/tests/test_provider.py --provider=filesystem"
wait $pid2

echo Done
