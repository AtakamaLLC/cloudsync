#!/bin/bash -e

pip install flit

VERSION=$(./verok.py "$(git describe --abbrev=0 --tags)")

echo ver $VERSION

# if this is changed, also change the .gitignore script
sed -i.bak "s/%VERSION%/$VERSION/" cloudsync/__init__.py

flit publish

# it's nice to put things back, because reasons
mv cloudsync/__init__.py.bak cloudsync/__init__.py
