SHELL := /bin/bash

env:
	virtualenv env

requirements: env
	. env/bin/activate && pip install -r requirements-dev.txt
	. env/bin/activate && pip install -r requirements.txt

lint:
	pylint cloudsync

test:
	pytest --durations=0 --workers=4 cloudsync/tests
