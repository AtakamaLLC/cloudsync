SHELL := /bin/bash

env:
	virtualenv env

requirements: env
	. env/bin/activate && pip install -r requirements-dev.txt
	. env/bin/activate && pip install -r requirements.txt
