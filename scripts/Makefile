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

apple_webauthn_root_ca.pem:
	$(CURl) -o apple_webauthn_root_ca.pem https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem

iana_cose_algs.csv:
	$(CURL) -o iana_cose_algs.csv https://www.iana.org/assignments/cose/algorithms.csv

cose_algs: iana_cose_algs.csv
	$(PYTHON) -c "from csv import DictReader; print({item.get('Value'): item.get('Name') for item in DictReader(open('./iana_cose_algs.csv'))})"

update_package_data: metadata.json apple_webauthn_root_ca.pem
	cp metadata.json apple_webauthn_root_ca.pem ../src/fido_mds/data/

clean:
	rm metadata.json globalsign_root_r3.der fido_alliance_mds.jwt iana_cose_algs.csv

all: metadata.json apple_webauthn_root_ca.pem

.DEFAULT_GOAL:= all
.PHONY: all
