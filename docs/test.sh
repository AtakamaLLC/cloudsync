#!/bin/bash -e

cd $(git rev-parse --show-toplevel)/docs

set -o xtrace

pip install virtualenv
virtualenv docenv
. docenv/bin/activate
pip install -r requirements.txt
rm -rf _build

make html > make.out 2>&1

grep 'WARNING' make.out && exit 1
grep 'build succeeded' make.out && exit 0

echo "unknown status"
exit 1
