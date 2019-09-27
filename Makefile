SHELL := /bin/bash

env:
	virtualenv env

requirements: env
	. env/bin/activate && pip install -r requirements-dev.txt
	. env/bin/activate && pip install -r requirements.txt

lint: _lint
	git fetch origin master
	./check_version.sh

_lint:
	pylint cloudsync --ignore tests && mypy cloudsync || { mypy cloudsync; exit 1; }

test:
	pytest --durations=0 -n=8 cloudsync/tests

format:
	autopep8 --in-place -r -j 8 cloudsync/
