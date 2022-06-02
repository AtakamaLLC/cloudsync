#!/bin/bash

set -o errexit

pip install pytest pytest-azurepipelines

pytest --durations=1 --cov=cloudsync  cloudsync/tests cloudsync/oauth/apiserver.py --timeout=300 &
pid1=$!

pytest --durations=1 --cov=cloudsync --cov-append --cov-report xml cloudsync/tests/test_provider.py --provider=filesystem &
pid2=$!

wait $pid1
wait $pid2
