#!/usr/bin/env python3
import sys
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
    from tests import genrsa
    rsatest = genrsa.test(s, baseurl)
    assert len(rsatest['result']) == 2, "RSA generation error"

    from tests import gendsa
    dsatest = gendsa.test(s, baseurl)
    assert len(dsatest['result']) == 2, "DSA generation error"
    
    from tests import genec
    ectest = genec.test(s, baseurl)
    assert len(ectest['result']) == 2, "EC generation error"

    from tests import genaes
    aestest = genaes.test(s, baseurl)
    assert len(aestest['result']) == 1, "AES generation error"

from tests import rsaendecrypt
assert rsaendecrypt.test(s, baseurl), "RSA encrypt and decrypt error"


print("All tests did not fail too obviously")
