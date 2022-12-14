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


SOFTHSM2_CONF=${SOFTHSM2_CONF:-$(pwd)/softhsm2.conf}
echo "$SOFTHSMCONF" > $SOFTHSM2_CONF
export SOFTHSM2_CONF


echo ""
echo "setting up a softhsm slot"
softhsm2-util --init-token --free --label SoftHSMLabel --so-pin "${PIN}" --pin "${PIN}" > /dev/null
if [ $? -ne 0 ]; then
	echo "Failed setup, exiting."
	exit 1
fi

sofile=$(ls -1 /usr/lib*/*/*softhsm2.so /usr/lib*/*softhsm2.so 2>/dev/null | head -n 1)

echo "We found a softhsm module in: '$sofile'"
if [ ! -f conf.yml ] ; then
    cat conf.yml.example | sed -e "s%MODULE_PATH%$sofile%" > conf.yml
    echo "You're conf.yml file is setup with this path"
else
    echo "You may consider to use this module in the conf.yml file"
fi

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
