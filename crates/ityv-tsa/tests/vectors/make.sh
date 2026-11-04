#!/bin/sh
# ityv-tsa test vectors: throwaway timestamp authorities (TSAs) and their
# RFC 3161 tokens, made with `openssl ts` (OpenSSL 3.0), and crafted
# variants (forge.py) that each break one rule.
#
#   sh crates/ityv-tsa/tests/vectors/make.sh
#
# Needs openssl (3.0 or later) and python3 (standard library only). Every
# run makes new keys and new times, so every output changes; the tests read
# the expected values from manifest.txt, which this script writes from
# `openssl ts -reply -text`, independently of the crate. Each valid token is
# also verified by `openssl ts -verify` before it is kept.
#
# The private keys live in a temporary directory that is deleted on exit:
# no private key is committed. These are test keys and certificates only.
#
# Outputs (all DER):
#   object-hash.bin      the timestamped data: a stand-in 64-octet checkpoint
#                        object hash; every query's imprint is its SHA-512
#                        (ADR-0034 §3)
#   <tsa>.crt            self-signed TSA certificates: CA:FALSE, key usage
#                        digitalSignature+nonRepudiation, critical EKU
#                        timeStamping
#   rsa3072-<rule>.crt   the rsa3072 key in certificates that each break one
#                        profile rule, or (policies-critical) use a form the
#                        profile accepts (embedded by forge.py)
#   <tsa>-<digest>*.tst  tokens (TimeStampToken, a CMS ContentInfo)
#   forged-*.tst         crafted variants of rsa3072-sha384.tst, and
#                        forged-p256-*.tst of p256-sha256.tst (forge.py)
#   manifest.txt         one line per valid token: how it was made and what
#                        OpenSSL reads in it
# The freetsa/ directory holds a real token and is not touched here (see
# freetsa/fetch.sh).
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd -- "$here"
rm -f -- ./*.tst ./*.crt manifest.txt
export PYTHONDONTWRITEBYTECODE=1

printf 'ityv-tsa test checkpoint object' | openssl dgst -sha3-512 -binary > object-hash.bin
: > "$work/empty.cnf"
echo 01 > "$work/serial"

# key NAME GENPKEY-OPTIONS...: a throwaway private key.
key() {
  name=$1
  shift
  openssl genpkey "$@" -out "$work/$name.key" 2>/dev/null
}

# certificate KEY NAME [BASIC [KEY-USAGE [EKU [EXTRA [SECTIONS]]]]]: a
# self-signed TSA certificate for KEY, valid for ten years from now. An empty
# or missing BASIC or KEY-USAGE is CA:FALSE and
# digitalSignature+nonRepudiation (both critical); a missing EKU is critical
# timeStamping and an empty one leaves the extension out; EXTRA is one more
# extension line and SECTIONS more configuration sections it refers to.
certificate() {
  basic=${3:-critical, CA:FALSE}
  usage=${4:-critical, digitalSignature, nonRepudiation}
  eku=${5-critical, timeStamping}
  extra=${6:-}
  sections=${7:-}
  {
    printf '[ req ]\ndistinguished_name = dn\nprompt = no\nx509_extensions = ext\n'
    printf '[ dn ]\nC = KR\nO = ityv test\nCN = ityv test TSA %s\n' "$1"
    printf '[ ext ]\nbasicConstraints = %s\nkeyUsage = %s\n' "$basic" "$usage"
    if [ -n "$eku" ]; then
      printf 'extendedKeyUsage = %s\n' "$eku"
    fi
    printf 'subjectKeyIdentifier = hash\n'
    if [ -n "$extra" ]; then
      printf '%s\n' "$extra"
    fi
    if [ -n "$sections" ]; then
      printf '%s\n' "$sections"
    fi
  } > "$work/$2.req"
  openssl req -new -x509 -config "$work/$2.req" -key "$work/$1.key" -days 3650 \
    -sha256 -out "$work/$2.pem"
  openssl x509 -in "$work/$2.pem" -outform DER -out "$work/$2.der"
}

# authority NAME GENPKEY-OPTIONS...: key and certificate, the certificate
# kept as NAME.crt.
authority() {
  name=$1
  shift
  key "$name" "$@"
  certificate "$name" "$name"
  cp -- "$work/$name.der" "$name.crt"
}

authority rsa2048 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
authority rsa3072 -algorithm RSA -pkeyopt rsa_keygen_bits:3072
authority rsa4096 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
authority rsa1024 -algorithm RSA -pkeyopt rsa_keygen_bits:1024
authority p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve
authority p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve
# The rsa3072 key again, in certificates that each break one profile rule
# (OpenSSL refuses to sign with most of them; forge.py embeds them).
certificate rsa3072 rsa3072-eku-noncritical "" "" "timeStamping"
certificate rsa3072 rsa3072-eku-two "" "" "critical, timeStamping, serverAuth"
certificate rsa3072 rsa3072-no-eku "" "" ""
certificate rsa3072 rsa3072-ca "critical, CA:TRUE"
certificate rsa3072 rsa3072-key-usage-sign "" "critical, digitalSignature, keyCertSign"
certificate rsa3072 rsa3072-cert-critical-ext "" "" "critical, timeStamping" \
  "1.2.3.4.5.6.7 = critical, ASN1:NULL"
# Accepted: a critical certificatePolicies with a CPS and a user notice in a
# BMPString, as Korean accredited and government (GPKI) profiles have.
certificate rsa3072 rsa3072-policies-critical "" "" "critical, timeStamping" \
  "certificatePolicies = critical, @policy" \
  "$(printf '[ policy ]\npolicyIdentifier = 1.2.3.4.10\nCPS.1 = "https://tsa.example/cps"\nuserNotice.1 = @notice\n[ notice ]\nexplicitText = "BMP:ityv test policy"')"
profiles="eku-noncritical eku-two no-eku ca key-usage-sign cert-critical-ext policies-critical"

# stamp OUT SIGNER DIGEST ESS-DIGEST QUERY-OPTIONS [CONFIG-LINES...]: one
# token from SIGNER over object-hash.bin.
stamp() {
  out=$1 signer=$2 digest=$3 ess=$4 query=$5
  shift 5
  {
    printf '[ tsa ]\ndefault_tsa = t\n[ t ]\n'
    printf 'serial = %s\ncrypto_device = builtin\n' "$work/serial"
    printf 'signer_cert = %s\nsigner_key = %s\n' "$work/$signer.pem" "$work/$signer.key"
    printf 'signer_digest = %s\ness_cert_id_alg = %s\ness_cert_id_chain = no\n' "$digest" "$ess"
    printf 'default_policy = 1.2.3.4.1\nother_policies = 1.2.3.4.2\n'
    printf 'digests = sha1, sha256, sha384, sha512\n'
    for line in "$@"; do
      printf '%s\n' "$line"
    done
  } > "$work/ts.cnf"
  # The query options are separate words on purpose.
  # shellcheck disable=SC2086
  openssl ts -query -data object-hash.bin $query -out "$work/query.tsq" 2>/dev/null
  openssl ts -reply -config "$work/ts.cnf" -queryfile "$work/query.tsq" \
    -token_out -out "$out" 2>/dev/null
  # Against the query: the imprint and, when the query has one, the nonce.
  openssl ts -verify -queryfile "$work/query.tsq" -in "$out" -token_in \
    -CAfile "$work/$signer.pem" -untrusted "$work/$signer.pem" -partial_chain >/dev/null 2>&1
}

# record TOKEN CERT SIGNATURE IMPRINT ESS: the manifest line of a valid token
# (ESS: the signing-certificate hash, sha1 for v1, else the v2 one).
record() {
  fields=$(python3 -I forge.py describe "$1" "$work/empty.cnf")
  printf '%s cert=%s signature=%s imprint=%s ess=%s %s\n' "$1" "$2" "$3" "$4" "$5" "$fields" \
    >> manifest.txt
}

full="accuracy = secs:1, millisecs:500, microsecs:100"

stamp rsa2048-sha256.tst rsa2048 sha256 sha256 "-sha512 -cert -no_nonce"
record rsa2048-sha256.tst rsa2048.crt RsaPkcs1Sha256 sha512 sha256
stamp rsa3072-sha384.tst rsa3072 sha384 sha256 "-sha512 -cert" "$full" \
  "ordering = yes" "tsa_name = yes" "clock_precision_digits = 3"
record rsa3072-sha384.tst rsa3072.crt RsaPkcs1Sha384 sha512 sha256
stamp rsa4096-sha512.tst rsa4096 sha512 sha512 "-sha512 -cert" "clock_precision_digits = 6"
record rsa4096-sha512.tst rsa4096.crt RsaPkcs1Sha512 sha512 sha512
stamp p256-sha256.tst p256 sha256 sha256 "-sha512 -cert" "accuracy = millisecs:20"
record p256-sha256.tst p256.crt EcdsaP256Sha256 sha512 sha256
stamp p384-sha384.tst p384 sha384 sha384 "-sha512 -cert -no_nonce" "tsa_name = yes"
record p384-sha384.tst p384.crt EcdsaP384Sha384 sha512 sha384
# P-384 with SHA-512 and an ESS v1 (SHA-1) binding, as freetsa.org signs.
stamp p384-sha512-essv1.tst p384 sha512 sha1 "-sha512 -cert" "ordering = yes"
record p384-sha512-essv1.tst p384.crt EcdsaP384Sha512 sha512 sha1
# No certReq: the token embeds no certificate.
stamp rsa2048-nocert.tst rsa2048 sha256 sha256 "-sha512 -no_nonce"
record rsa2048-nocert.tst rsa2048.crt RsaPkcs1Sha256 sha512 sha256
# The second policy.
stamp rsa2048-policy2.tst rsa2048 sha256 sha256 "-sha512 -cert -tspolicy 1.2.3.4.2"
record rsa2048-policy2.tst rsa2048.crt RsaPkcs1Sha256 sha512 sha256
# A SHA-256 imprint.
stamp rsa2048-imprint256.tst rsa2048 sha256 sha256 "-sha256 -cert"
record rsa2048-imprint256.tst rsa2048.crt RsaPkcs1Sha256 sha256 sha256
# Refused whatever the pin: P-256 with SHA-384, a 1024-bit modulus, a SHA-1 imprint.
stamp p256-sha384.tst p256 sha384 sha256 "-sha512 -cert"
stamp rsa1024-sha256.tst rsa1024 sha256 sha256 "-sha512 -cert"
stamp rsa2048-imprint1.tst rsa2048 sha256 sha256 "-sha1 -cert"

set --
for profile in $profiles; do
  set -- "$@" "$profile=$work/rsa3072-$profile.der"
  cp -- "$work/rsa3072-$profile.der" "rsa3072-$profile.crt"
done
python3 -I forge.py forge "$work/rsa3072.key" sha384 rsa3072-sha384.tst rsa3072.crt . "$@"
# The P-256 order n (FIPS 186-5, SEC 2).
python3 -I forge.py ecdsa p256-sha256.tst \
  FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 . p256
