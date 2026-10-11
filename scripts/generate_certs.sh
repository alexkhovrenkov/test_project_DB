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

set -e   # stop at the first error

cd "$(dirname "$0")/.."   # run from the project root, wherever we are called from
mkdir -p certs
cd certs

# 1. Our Certificate Authority (CA).
#    "req -x509" creates a self-signed certificate: the CA vouches for itself.
#    -nodes means "do not password-protect the private key".
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout ca-key.pem -out ca.pem \
    -subj "/CN=University Demo CA"

# 2. The server's private key and a "certificate signing request" (CSR).
#    The CSR says: "please certify that this public key belongs to localhost".
openssl req -newkey rsa:2048 -nodes \
    -keyout server-key.pem -out server-req.pem \
    -subj "/CN=localhost"

# 3. The CA signs the request -> server certificate.
#    subjectAltName is the list of names the certificate is valid for.
#    Clients compare it with the host name they connected to.
openssl x509 -req -in server-req.pem -days 365 \
    -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out server-cert.pem \
    -extfile <(printf "subjectAltName=DNS:localhost")

# 4. A different CA that has nothing to do with our server (for the TLS attack test).
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout untrusted-ca-key.pem -out untrusted-ca.pem \
    -subj "/CN=Some Other CA"

# Clean up helper files we no longer need.
rm -f server-req.pem ca.srl

# MariaDB inside the container runs as a different user than you, so it must be
# able to read the key file. Acceptable for a local demo, NOT for production.
chmod 644 server-key.pem

# Show what we made: who the certificate belongs to and who signed it.
echo
openssl x509 -in server-cert.pem -noout -subject -issuer -ext subjectAltName
openssl verify -CAfile ca.pem server-cert.pem
