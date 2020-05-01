#!/bin/bash

set -o errexit

pip install pytest pytest-azurepipelines

pytest --durations=1 --cov=cloudsync  -n=2 cloudsync/tests cloudsync/oauth/apiserver.py --timeout=300

pytest --durations=1 --cov=cloudsync --cov-append --cov-report xml -n=2 cloudsync/tests/test_provider.py --provider=filesystem
