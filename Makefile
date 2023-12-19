SHELL := /bin/bash

unit-test:
	cd src && coverage run --source=coguard_coverity_translator -m pytest --capture=sys -x
	cd src && coverage html -i --directory=coverage_output --fail-under=80
lint:
	find src -type f -name "*.py" -not -path "*/tests/*" | xargs pylint --rcfile="./.pylint.rc"
