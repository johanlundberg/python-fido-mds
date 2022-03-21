TOPDIR:=        $(abspath .)
SOURCE=         $(TOPDIR)/src

reformat:
	isort --line-width 120 --atomic $(SOURCE)
	black --line-length 120 --target-version py38 --skip-string-normalization $(SOURCE)

typecheck:
	MYPYPATH=$(SOURCE) mypy --ignore-missing-imports -p fido_mds
