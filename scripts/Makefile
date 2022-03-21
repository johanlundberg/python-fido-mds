CERT_URL=http://secure.globalsign.com/cacert/root-r3.crt
MDS_URL=https://mds.fidoalliance.org

CURL=$(shell which curl) -s
PYTHON=$(shell which python)

globalsign_root_r3.der:
	$(CURL) -o globalsign_root_r3.der $(CERT_URL)

fido_alliance_mds.jwt:
	$(CURL) -o fido_alliance_mds.jwt ${MDS_URL}

metadata.json: globalsign_root_r3.der fido_alliance_mds.jwt
	$(PYTHON) update_metadata.py > metadata.json

all: metadata.json

.DEFAULT_GOAL:= all
.PHONY: all
