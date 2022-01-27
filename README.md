
# Dependencies
To setup a HSM locally the softhsm2-util, p11tool packages are required, to install:
```bash
brew install softhsm gnutls libp11  # Mac OSX
apt-get install softhsm2 gnutls-bin libengine-pkcs11-openssl mlocate python3-dev gcc-x86-64-linux-gnu # Debian, Ubuntu, etc.
yum install softhsm gnutls-utils openssl-pkcs11 mlocate # CentOS
dnf install softhsm gnutls-utils openssl-pkcs11 mlocate # Fedora
zypper install gnutls, libgnutls30, p11-kit, p11-kit-tools mlocate # OpenSuse
```


# Test everything
in 2 terminals start:
```bash 
make runtest
make testrun
```
