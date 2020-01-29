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

lint:
	pylint cloudsync --enable=duplicate-code --ignore tests && mypy cloudsync || { mypy cloudsync; exit 1; }

test:
	pytest --cov=cloudsync --durations=1 -n=8 cloudsync/tests --full-trace --timeout=10
	docs/test.sh

coverage: test
	coverage xml
	diff-cover coverage.xml --compare-branch=$(git merge-base HEAD origin/master)


format:
	autopep8 --in-place -r -j 8 cloudsync/

bumpver:
	./bumpver.py
