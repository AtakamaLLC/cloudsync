SHELL := /bin/bash

env:
	virtualenv env

requirements: env
	. env/bin/activate && pip install -r requirements-dev.txt
	. env/bin/activate && pip install -r requirements.txt

lint: _lint
	git fetch origin master

_lint:
	pylint cloudsync --ignore tests && mypy cloudsync || { mypy cloudsync; exit 1; }

test:
	pytest --cov=cloudsync --durations=0 -n=8 cloudsync/tests

coverage:
	pytest --cov-report html --cov=cloudsync -n=8 cloudsync/tests

format:
	autopep8 --in-place -r -j 8 cloudsync/

bumpver:
	./bumpver.py
