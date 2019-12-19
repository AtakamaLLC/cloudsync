SHELL := /bin/bash
ifeq ($(OS),Windows_NT)
	ENVBIN="scripts"
else
	ENVBIN="bin"
endif

env:
	virtualenv env

requirements: env
	. env/$(ENVBIN)/activate && pip install -r requirements-dev.txt
	. env/$(ENVBIN)/activate && pip install -r requirements.txt

lint: _lint
	git fetch origin master

_lint:
	pylint cloudsync --enable=duplicate-code --ignore tests && mypy cloudsync || { mypy cloudsync; exit 1; }

test:
	pytest --cov=cloudsync --durations=0 -n=8 cloudsync/tests --full-trace --timeout=10
	docs/test.sh

coverage:
	pytest --cov-report html --cov=cloudsync -n=8 cloudsync/tests

format:
	autopep8 --in-place -r -j 8 cloudsync/

bumpver:
	./bumpver.py
