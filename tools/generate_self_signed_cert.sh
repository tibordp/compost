#!/bin/sh
set -e

# Generate a self-signed certificate for the server to use for TLS.
# This is only for development and testing purposes.
openssl req -x509 -newkey rsa:4096 -keyout localhost.key -out localhost.crt -days 365 -nodes -subj '/CN=localhost'
