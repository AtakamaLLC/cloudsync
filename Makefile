SHELL := /bin/bash
PYTEST = pytest -rfE --cov=cloudsync --durations=1 -n=4 cloudsync/tests --tb=short --timeout=20

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

lint: lint-pylint lint-mypy lint-md lint-deps

lint-pylint:
	pylint cloudsync --enable=duplicate-code --ignore tests

lint-mypy:
	mypy cloudsync

lint-md: ./node_modules/.bin/remark
	./node_modules/.bin/remark -f docs/*.md *.md

lint-deps:
	python check-deps.py

test: test-py test-doc

.coverage: $(shell find cloudsync -type f -name '*.py')
	$(PYTEST)

test-doc:
	docs/test.sh

test-py:
	$(PYTEST)

coverage.xml: .coverage
	coverage xml

coverage: coverage.xml
	diff-cover coverage.xml --compare-branch=$(BASE)

format:
	autopep8 --in-place -r -j 8 cloudsync/

bumpver:
	./bumpver.py

./node_modules/.bin/remark:
	npm install

.PHONY: test test-py test-doc lint format bumpver env requirements coverage lint-md lint-deps
