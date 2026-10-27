#!/bin/sh
# Regenerates the key fixtures with OpenSSL >= 3.5 (ML-DSA needs 3.5).
# Erlang cannot generate ML-DSA certificates (public_key:pkix_test_root_cert/2
# and pem_entry_encode/2 have no ML-DSA clause as of OTP 29.1), hence files.
set -e
cd "$(dirname "$0")"
for level in 44 65 87; do
  openssl genpkey -algorithm ML-DSA-$level -out ml_dsa_$level.pem
  openssl req -x509 -new -key ml_dsa_$level.pem -subj "/CN=ExSaml ML-DSA-$level test" \
    -days 36500 -out ml_dsa_$level.crt
done
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_p256_pkcs8.pem
openssl ec -in ec_p256_pkcs8.pem -out ec_p256_sec1.pem 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_2048_pkcs8.pem
