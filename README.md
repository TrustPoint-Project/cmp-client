# CMPClient Utility

This repository contains a Python implementation for interacting with a Certificate Management Protocol (CMP) server. The utility provides various functionalities such as certificate enrollment, renewal, rekeying, revocation, and retrieval of CA certificates. The script is designed to be modular and extendable, using the OpenSSL command-line tool to perform its operations.

> [!CAUTION]
> The CMP client is currently in an **early technology preview** (alpha) state. Do not use it in production.


## Features

* **Client Initialization**: Set up a CMP client with the necessary certificates, keys, and server details.
* **Certificate Enrollment**: Generate a new key pair, create a CSR, and enroll for a new certificate.
* **Certificate Renewal**: Renew an existing certificate by creating a new CSR with the existing key.
* **Rekey Certificate**: Generate a new key pair, create a CSR, and request a certificate with the new key.
* **Certificate Revocation**: Revoke an existing certificate by specifying the certificate's issuer and serial number.
* **Retrieve CA Certificates**: Retrieve CA certificates from the server.

### Not implemented
* **Retrieve a Root CA Update**
* **Retrieve the Certificate Request Template**
* **Retrieve a Certificate Revocation List (CRL)**

## Installation

**1. Clone the repository:**
```bash
git clone https://github.com/TrustPoint-Project/cmp-client.git
cd CMPClient
```
**2. Install dependencies:**

Ensure you have Python 3.8+ installed. Install the required Python packages using pip:
```bash
pip install -r requirements.txt
```
**3. Configure OpenSSL:**

Make sure OpenSSL is installed and accessible from your command line.

## Usage

### Initialize the CMP Client
```python
from python.client.src.cmp_client import CMPClient

ca_server = "127.0.0.1:8000"
ca_path = "/ejbca/publicweb/cmp/your_cmp_profile"
cert = "./path_to_your_cert.pem"
key = "./path_to_your_key.pem"
trusted_cert_chain = "./path_to_ca_cert_chain.pem"

client = CMPClient(ca_server=ca_server, ca_path=ca_path, cert=cert, key=key, trusted_cert_chain=trusted_cert_chain)
```
### Enroll a New Certificate
```python
dn_info = {
    'C': 'DE',
    'ST': 'BW',
    'L': 'Freudenstadt',
    'O': 'Campus Schwarzwald',
    'OU': 'Trustpoint',
    'CN': 'client.trustpoint.com'
}

san_info = {
    'DNS': ['example.com', 'www.example.com'],
    'IP': ['192.168.1.1'],
    'URI': ['http://example.com']
}


cert_file, chain_file = client.initialization(dn_info, san_info, key_algorithm='RSA', key_size=4096)
```
### Renew an Existing Certificate
```python
cert_file, chain_file = client.certification(key_path, # path to the old key
                                             old_cert=old_cert) # path to the old cert
```
### Rekey a Certificate
```python
# For key update one needs to provide the old certificate and old key
client = CMPClient(ca_server=ca_server, 
                   ca_path=ca_path, 
                   cert=certificate_to_be_updated, 
                   key=oldcert_key, 
                   trusted_cert_chain=trusted_cert_chain)

cert_file, chain_file = client.keyupdate()
```
### Revoke a Certificate
```python
client.revoke_cert("/path/to/cert.pem", reason=1)
```
### Retrieve CA Certificates
```python
ca_cert_file = client.getcacerts()
```
