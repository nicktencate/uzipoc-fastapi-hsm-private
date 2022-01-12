
# Dependencies
To setup a HSM locally the softhsm2-util, p11tool packages are required, to install:
```bash
brew install softhsm gnutls libp11  # Mac OSX
apt-get install softhsm2 gnutls-bin libengine-pkcs11-openssl mlocate python3-dev gcc-x86-64-linux-gnu # Debian, Ubuntu, etc.
yum install softhsm gnutls-utils openssl-pkcs11 mlocate # CentOS
dnf install softhsm gnutls-utils openssl-pkcs11 mlocate # Fedora
```

# TODO:

Explain:
* RSA\_PKCS, RSA\_PKCS\_PSS

* SHA_*_PKCS(_PSS)

* objtypes

Support:

Certificates, importing certificates, loading public keys, loading private keys

Examples:

Sign hash:


    curl -X 'POST' -H 'accept: application/json' -H 'Content-Type: application/json' 'http://localhost:8000/hsm/softhsm/HSM-000/sign' -d '
    { "label": "RSA-1", 
       "data": "RzKH+CmNunFjqJeQiVj3wOrnM+JdLgJ5kuou3JvtL6g=",
       "mechanism": "RSA_PKCS_PSS", 
       "hashmethod": "sha256"}'

Result:
    {
      "module": "softhsm",
      "slot": "HSM-000",
      "result": "Nr/Elc9jzaKlEWLTxLRuzfLYWk6hnbf9zc2Xitsn7Utau+wOXBt2GOKJvMndcuO3OGpj+qZ6nPeBjW9j24XTmMlwUR1x8ukEz5RJtKo+EncResQIPDG+MobunMdE4FBMGlrL0fzqJOuhXeVulfQ6bvF5UAJdd5T6jKRPkCt0R8EMJSJAse+W+IBhMw2a44PI6RruPgQT7bs+KNpVzPudFbNBUdqxeQFAve0q2mFuegWtvN3r5vTUifbUcHd7s72ITJEc0TC09cz/nSj1FQlZPJ3djuRKDEK2EmrWjLPuT9BKDBDs5uZgC3EJXXbBUH2tlnNS+5/pafAqIS6QnnSv1g=="
}

Verify hash:


