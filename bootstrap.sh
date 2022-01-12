#!/bin/bash

PIN=0000

if [ ! -e secrets ];
then
	echo "Creating secrets directory"
	mkdir secrets
fi

echo "saving pincode"
echo "${PIN}" > secrets/utimaco-000.pin

test -d "${PWD}/tokens/" && (echo "removing old token directory"; rm -r "${PWD}/tokens/" )
mkdir "${PWD}/tokens/"

SOFTHSMCONF=$(cat <<EOF
directories.tokendir = ${PWD}/tokens/
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF
)

echo "$SOFTHSMCONF" > softhsm2.conf
SOFTHSM2_CONF=$(pwd)/softhsm2.conf
export SOFTHSM2_CONF


echo ""
echo "setting up utimaco"
softhsm2-util --init-token --free --label SomeLabel --so-pin "${PIN}" --pin "${PIN}" > /dev/null
if [ $? -ne 0 ]; then
	echo "Failed setup, exiting."
	exit 1
fi
TOKEN=$(p11tool --list-token-urls | grep "token=SomeLabel"| head -n 1)

echo ""
echo "generate key"
p11tool --login --set-pin "${PIN}" --generate-rsa --bits 2048 --label changeme "${TOKEN}" > /dev/null
if [ $? -ne 0 ]; then
	echo "Failed setup, exiting."
	exit 1
fi

echo ""
echo "generate cert"
openssl req -new -x509 -nodes -subj /CN=testCertificate -engine pkcs11 -keyform engine -key "${TOKEN};pin-value=${PIN}" > secrets/utimaco.pem
if [ $? -ne 0 ]; then
	echo "Failed setup, exiting."
	exit 1
fi
echo ""
echo "getting label"
LABEL=$(openssl x509 -noout -serial -in secrets/utimaco.pem | cut -d '=' -f2)
echo ""
echo "Setting lbel"
p11tool --set-pin "${PIN}" --set-label "${LABEL}" --login "${TOKEN};object=changeme;type=public"
p11tool --set-pin "${PIN}" --set-label "${LABEL}" --login "${TOKEN};object=changeme;type=private"
if [ $? -ne 0 ]; then
	echo "Failed setup, exiting."
	exit 1
fi
echo "Utimaco label: ${LABEL}"

sofile=$(locate -i softhsm2.so | head -n 1)
echo "We found a softhsm module in: '$sofile'"
echo "You may consider to use this module in the conf.yml file"
echo
echo
echo "you might want to add SOFTHSM2_CONF to your bash profile or similar"
echo
echo
echo "	export SOFTHSM2_CONF=$SOFTHSM2_CONF"
echo
echo "	cat 'export SOFTHSM_CONF=$SOFTHSM2_CONF' >> ~/.bashrc"
echo 
echo 
