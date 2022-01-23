#!/bin/bash
FAILURE=0
for cert in tests/*leaf*; do echo "==== $cert ==="; openssl verify -CAfile ${cert/leaf/root} $cert || FAILURE=1; done
exit $FAILURE
