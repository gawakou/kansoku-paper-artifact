.PHONY: test pre-release lab-selftest lab-install lab-build lab-up lab-status lab-test lab-recommend-test lab-reset lab-down

PYTHON ?= python

test:
	$(PYTHON) -m pytest -q

pre-release:
	./scripts/pre_release_check.sh

lab-selftest:
	./lab/scripts/lab-selftest.sh

lab-install:
	./lab/vm/bootstrap-ubuntu.sh

lab-build:
	./lab/scripts/lab-build.sh

lab-up:
	./lab/scripts/lab-up.sh

lab-status:
	./lab/scripts/lab-status.sh

lab-test:
	./lab/scripts/lab-test.sh

lab-recommend-test:
	./lab/scripts/lab-test.sh

lab-reset:
	./lab/scripts/lab-reset.sh

lab-down:
	./lab/scripts/lab-down.sh
