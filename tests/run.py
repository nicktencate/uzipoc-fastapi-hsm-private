#!/usr/bin/env python3
import sys
from time import time
BASE = "http://localhost:8000/hsm/"

import requests
s = requests.Session()

s.get('http://localhost:8000/hsm/list').json()

module = s.get(BASE + 'list').json()['modules'][0]
slot = s.get(BASE + "%s" %  module).json()['slots'][0]
baseurl = BASE + "%s/%s" % (module, slot)

objects = s.get(baseurl).json()['objects']
if len(sys.argv) < 2:
  assert objects == {}, 'Please run this on a clean softhsm'



if len(sys.argv) < 2:
    start = time()
    from tests import genrsa
    rsatest = genrsa.test(s, baseurl)
    assert len(rsatest['result']) == 2, "RSA generation error"
    print("Time: ",time()-start)

    start = time()
    from tests import gendsa
    dsatest = gendsa.test(s, baseurl)
    assert len(dsatest['result']) == 2, "DSA generation error"
    print("Time: ",time()-start)
    
    start = time()
    from tests import genec
    ectest = genec.test(s, baseurl)
    assert len(ectest['result']) == 2, "EC generation error"
    print("Time: ",time()-start)

    start = time()
    from tests import genedwards
    edtest = genedwards.test(s, baseurl)
    assert len(edtest['result']) == 2, "ED generation error"
    print("Time: ",time()-start)

    start = time()
    from tests import genaes
    aestest = genaes.test(s, baseurl)
    assert len(aestest['result']) == 1, "AES generation error"
    print("Time: ",time()-start)

start = time()
from tests import rsaendecrypt
assert rsaendecrypt.test(s, baseurl), "RSA encrypt and decrypt error"
print("Time: ",time()-start)

start = time()
from tests import aesendecrypt
assert aesendecrypt.test(s, baseurl), "AES encrypt and decrypt error"
print("Time: ",time()-start)

start = time()
from tests import rsasign
assert rsasign.test(s, baseurl), "RSA sign and verify error"
print("Time: ",time()-start)


print("All tests did not fail too obviously")
