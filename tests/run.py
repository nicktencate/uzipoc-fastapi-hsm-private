#!/usr/bin/env python3
import sys
from time import time
import requests

from tests import genrsa
from tests import gendsa
from tests import genec
from tests import genedwards
from tests import genaes

from tests import rsaendecrypt
from tests import aesendecrypt
from tests import rsasign
from tests import ecsign
from tests import edsign
from tests import rsacert
from tests import eccert
from tests import edcert

BASE = "http://localhost:8000/hsm/"

s = requests.Session()

s.get("http://localhost:8000/hsm/list").json()

module = s.get(BASE + "list").json()["modules"][0]
slot = s.get(BASE + f"{module}").json()["slots"][0]
baseurl = BASE + f"{module}/{slot}"

objects = s.get(baseurl).json()["objects"]
if len(sys.argv) < 2:
    assert objects == {}, "Please run this on a clean softhsm"


if len(sys.argv) < 2:
    start = time()
    rsatest = genrsa.test(s, baseurl)
    assert len(rsatest["result"]) == 2, "RSA generation error"
    print("Time: ", time() - start)

    start = time()
    dsatest = gendsa.test(s, baseurl)
    assert len(dsatest["result"]) == 2, "DSA generation error"
    print("Time: ", time() - start)

    start = time()
    ectest = genec.test(s, baseurl)
    assert len(ectest["result"]) == 2, "EC generation error"
    print("Time: ", time() - start)

    start = time()
    edtest = genedwards.test(s, baseurl)
    assert len(edtest["result"]) == 2, "ED generation error"
    print("Time: ", time() - start)

    start = time()
    aestest = genaes.test(s, baseurl)
    assert len(aestest["result"]) == 1, "AES generation error"
    print("Time: ", time() - start)

start = time()
assert rsaendecrypt.test(s, baseurl), "RSA encrypt and decrypt error"
print("Time: ", time() - start)

start = time()
assert aesendecrypt.test(s, baseurl), "AES encrypt and decrypt error"
print("Time: ", time() - start)

start = time()
assert rsasign.test(s, baseurl), "RSA sign and verify error"
print("Time: ", time() - start)

start = time()
assert ecsign.test(s, baseurl), "EC sign and verify error"
print("Time: ", time() - start)

start = time()
assert edsign.test(s, baseurl), "ED sign and verify error"
print("Time: ", time() - start)

start = time()
assert rsacert.test(s, baseurl), "RSA cert create error"
print("Time: ", time() - start)

start = time()
assert eccert.test(s, baseurl), "EC cert create error"
print("Time: ", time() - start)

start = time()
assert edcert.test(s, baseurl), "ED cert create error"
print("Time: ", time() - start)

print("All tests did not fail too obviously")
