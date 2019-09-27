#!/bin/bash -e

pip install flit

VERSION=$(./verok.py "$(git tag)")

echo ver $VERSION

sed -i.bak "s/%VERSION%/$VERSION/" cloudsync/__init__.py

cat cloudsync/__init__.py

flit publish

mv cloudsync/__init__.py.bak cloudsync/__init__.py
