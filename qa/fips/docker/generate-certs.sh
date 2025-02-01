#!/bin/bash

cd "$(dirname "$0")"

mkdir -p certs

# Create OpenSSL config
cat > certs/openssl.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = logstash

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = logstash
DNS.2 = elasticsearch
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

# Generate CA
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout certs/ca.key -out certs/ca.crt \
  -subj "/CN=Elastic-CA"

# Generate server cert
openssl req -newkey rsa:4096 -nodes \
  -keyout certs/es01.key -out certs/es01.csr \
  -config certs/openssl.cnf

openssl x509 -req -in certs/es01.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/es01.crt -days 365 \
  -extfile certs/openssl.cnf -extensions v3_req

# Set appropriate permissions
chmod 644 certs/ca.crt certs/es01.crt
chmod 600 certs/es01.key

# Clean up temporary files
rm certs/es01.csr certs/ca.srl certs/openssl.cnf