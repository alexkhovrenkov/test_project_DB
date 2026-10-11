#!/bin/bash
# generate_certs.sh
# Creates local development TLS certificates in the certs/ folder.
#
#   bash scripts/generate_certs.sh
#
# What gets created:
#   ca.pem / ca-key.pem                   Our own tiny "University CA". The client trusts ca.pem.
#   server-cert.pem / server-key.pem      The MariaDB server's certificate, SIGNED by our CA,
#                                         valid for the host name "localhost".
#   untrusted-ca.pem / untrusted-ca-key.pem
#                                         A second, unrelated CA. Used only by the tests to show
#                                         that a client trusting the WRONG CA refuses to connect.
#
# These are for local development only. A real deployment would use
# certificates from the organisation's real CA.

set -euo pipefail   # stop at the first error, on unset variables and failed pipes
umask 077           # new files (keys!) are private by default

cd "$(dirname "$0")/.."   # run from the project root, wherever we are called from

# openssl prints a lot of progress dots. Hide them, but show everything if a command fails.
quietly() {
    local output
    if ! output=$("$@" 2>&1); then
        echo "$output" >&2
        return 1
    fi
}
mkdir -p certs
cd certs

# 1. Our Certificate Authority (CA).
#    "req -x509" creates a self-signed certificate: the CA vouches for itself.
#    -nodes means "do not password-protect the private key".
quietly openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout ca-key.pem -out ca.pem \
    -subj "/CN=University Demo CA"

# 2. The server's private key and a "certificate signing request" (CSR).
#    The CSR says: "please certify that this public key belongs to localhost".
quietly openssl req -newkey rsa:2048 -nodes \
    -keyout server-key.pem -out server-req.pem \
    -subj "/CN=localhost"

# 3. The CA signs the request -> server certificate.
#    subjectAltName is the list of names the certificate is valid for.
#    Clients compare it with the host name they connected to.
quietly openssl x509 -req -in server-req.pem -days 365 \
    -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out server-cert.pem \
    -extfile <(printf "subjectAltName=DNS:localhost")

# 4. A different CA that has nothing to do with our server (for the TLS attack test).
quietly openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout untrusted-ca-key.pem -out untrusted-ca.pem \
    -subj "/CN=Some Other CA"

# Clean up helper files we no longer need.
rm -f server-req.pem ca.srl

# Private keys must be readable by their owner only. (docker-compose.yml copies
# the server key into the container with the right owner, so no loosening of
# permissions on the host is needed.)
chmod 600 ./*-key.pem
umask_check=$(stat -c '%a' server-key.pem 2>/dev/null || stat -f '%Lp' server-key.pem)
if [ "$umask_check" != "600" ]; then
    echo "ERROR: server-key.pem has mode $umask_check, expected 600" >&2
    exit 1
fi

# Show what we made: who the certificate belongs to and who signed it.
echo
openssl x509 -in server-cert.pem -noout -subject -issuer -ext subjectAltName
openssl verify -CAfile ca.pem server-cert.pem
