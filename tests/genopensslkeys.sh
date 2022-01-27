cd tests/
openssl genpkey -algorithm Ed25519 -out openssl-ed25519key.pem
openssl pkey -outform DER -pubout -in openssl-ed25519key.pem -outform PEM -out openssl-ed25519public.pem 
openssl genpkey -algorithm Ed25519 -out openssl-x25519key.pem
openssl pkey -outform DER -pubout -in openssl-x25519key.pem -outform PEM -out openssl-x25519public.pem 
openssl ecparam -name prime256v1 -genkey -noout -out openssl-eckey.pem
openssl ec -in openssl-eckey.pem -pubout -out openssl-ecpublic.pem
openssl genrsa -out openssl-rsakey.pem 2048
openssl rsa -in openssl-rsakey.pem -outform PEM -pubout -out openssl-rsapublic.pem
echo "test42424242" | openssl cms  -aes256 -encrypt -outform pem test-leaf-cert-ec-sha256_ecdsa.pem > cms-encrypted-sha256_ecdsa.pem
