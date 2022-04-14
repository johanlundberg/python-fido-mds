TOPDIR:=        $(abspath .)
SOURCE=         $(TOPDIR)/src
PYTHON=$(shell which python)
PIP=$(shell which pip)

reformat:
	isort --line-width 120 --atomic $(SOURCE)
	black --line-length 120 --skip-string-normalization $(SOURCE)

typecheck:
	MYPYPATH=$(SOURCE) mypy --ignore-missing-imports -p fido_mds

update_package_data:
	cd $(TOPDIR)/scripts && make update_package_data

test:
	pytest src

build:
	$(PIP) install build[virtualenv]
	$(PYTHON) -m build
