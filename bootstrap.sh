#!/bin/bash

PIN=0000

if [ ! -e secrets ];
then
	echo "Creating secrets directory"
	mkdir secrets
fi

echo "saving pincode"
echo "${PIN}" > secrets/someslot-000.pin

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
echo "setting up a softhsm slot"
softhsm2-util --init-token --free --label SoftHSMLabel --so-pin "${PIN}" --pin "${PIN}" > /dev/null
if [ $? -ne 0 ]; then
	echo "Failed setup, exiting."
	exit 1
fi

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
