#!/bin/sh
# Fetches one real RFC 3161 token from freetsa.org (a free public TSA) for
# the interoperability test, over the same imprint as the generated vectors:
# SHA-512 of ../object-hash.bin, with certReq and a nonce.
#
#   sh crates/ityv-tsa/tests/vectors/freetsa/fetch.sh
#
# Needs curl and openssl. The downloads are untrusted data: they go to a new
# empty temporary directory, are only parsed by openssl (never executed),
# and only the token and the TSA certificate (DER) are copied here:
#   token.tst  the TimeStampToken taken out of the TimeStampResp
#   tsa.crt    https://freetsa.org/files/tsa.crt in DER, the pinned certificate
#   cacert.pem https://freetsa.org/files/cacert.pem, to cross-check with openssl
# The test pins tsa.crt; the root CA is not used by the crate.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

openssl ts -query -data "$here/../object-hash.bin" -sha512 -cert -out "$work/query.tsq"
curl -sS --fail --max-time 60 -H 'Content-Type: application/timestamp-query' \
  --data-binary "@$work/query.tsq" -o "$work/reply.tsr" https://freetsa.org/tsr
curl -sS --fail --max-time 60 -o "$work/tsa.crt" https://freetsa.org/files/tsa.crt
curl -sS --fail --max-time 60 -o "$work/cacert.pem" https://freetsa.org/files/cacert.pem

openssl ts -reply -in "$work/reply.tsr" -token_out -out "$work/token.tst"
openssl x509 -in "$work/tsa.crt" -outform DER -out "$work/tsa.der"
openssl x509 -in "$work/cacert.pem" -out "$work/cacert.checked.pem"
openssl ts -verify -data "$here/../object-hash.bin" -in "$work/token.tst" -token_in \
  -CAfile "$work/cacert.checked.pem" -untrusted "$work/tsa.crt"

cp -- "$work/token.tst" "$here/token.tst"
cp -- "$work/tsa.der" "$here/tsa.crt"
cp -- "$work/cacert.checked.pem" "$here/cacert.pem"
openssl ts -reply -in "$here/token.tst" -token_in -text

# The manifest line, as make.sh writes it. The algorithms are what
# freetsa.org used when this was written (read with `openssl asn1parse`):
# ECDSA P-384 with SHA-512 and an ESS signing-certificate v1 (SHA-1).
: > "$work/empty.cnf"
fields=$(PYTHONDONTWRITEBYTECODE=1 python3 -I "$here/../forge.py" describe "$here/token.tst" "$work/empty.cnf")
printf 'token.tst cert=tsa.crt signature=EcdsaP384Sha512 imprint=sha512 ess=sha1 %s\n' "$fields" \
  > "$here/manifest.txt"
