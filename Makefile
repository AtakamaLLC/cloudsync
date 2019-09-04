SHELL := /bin/bash

env:
	virtualenv env

requirements: env
	. env/bin/activate && pip install -r requirements-dev.txt
	. env/bin/activate && pip install -r requirements.txt

lint:
	pylint cloudsync --ignore tests
	git fetch origin master
	./check_version.sh

test:
	pytest --durations=0 -n=4 cloudsync/tests

format:
	autopep8 --in-place -r -j 8 cloudsync/
