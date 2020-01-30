SHELL := /bin/bash

ifeq ($(OS),Windows_NT)
	ENVBIN="scripts"
else
	ENVBIN="bin"
endif

BASE := $(shell git merge-base HEAD origin/master)

env:
	virtualenv env

requirements: env
	. env/$(ENVBIN)/activate && pip install -r requirements-dev.txt
	. env/$(ENVBIN)/activate && pip install -r requirements.txt

lint:
	pylint cloudsync --enable=duplicate-code --ignore tests && mypy cloudsync || { mypy cloudsync; exit 1; }

test: test-py test-doc

test-py:
	pytest --cov=cloudsync --durations=1 -n=8 cloudsync/tests --full-trace --timeout=10

test-doc:
	docs/test.sh

.coverage: test-py

coverage.xml: .coverage
	coverage xml

coverage: coverage.xml
	diff-cover coverage.xml --compare-branch=$(BASE)

format:
	autopep8 --in-place -r -j 8 cloudsync/

bumpver:
	./bumpver.py

.PHONY: test test-py test-doc lint format bumpver env requirements coverage
