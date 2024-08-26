import logging
import traceback
from src.cmp_client import CMPClient
from src.crypto_utils import CryptoUtils

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('cmp-client')


def initialize_client(ca_server, ca_path, cert, key, trusted_cert_chain):
    """
    Initialize and return a CMPClient instance.
    """
    return CMPClient(ca_server=ca_server, ca_path=ca_path, cert=cert, key=key, trusted_cert_chain=trusted_cert_chain)

def test_initialization(client, dn_info, san_info, key_algorithm='RSA', key_size=4096):
    """
    Enroll a new certificate.
    """
    try:
        cert_file, chain_file = client.initialization(dn_info, san_info, key_algorithm, key_size=key_size, implicit_confirm=True, detailed_logging=True)
        logger.info(f"Certificate saved at: {cert_file}")
        logger.info(f"Certificate chain saved at: {chain_file}")
    except Exception as e:
        logger.error("Failed to enroll new certificate")
        logger.error(e)
        logger.debug(traceback.format_exc())

def test_certification(client, key_path, old_cert, key_password=None):
    """
    Renew an existing certificate.
    """
    try:
        cert_file, chain_file = client.certification(key_path, key_password=key_password, old_cert=old_cert, implicit_confirm=True, detailed_logging=True)
        logger.info(f"Certificate saved at: {cert_file}")
        logger.info(f"Certificate chain saved at: {chain_file}")
    except Exception as e:
        logger.error("Failed to renew certificate")
        logger.error(e)
        logger.debug(traceback.format_exc())

def test_key_update(client):
    """
    Rekey an existing certificate.
    """
    try:
        cert_file, chain_file = client.keyupdate(implicit_confirm=True, detailed_logging=True)
        logger.info(f"Certificate saved at: {cert_file}")
        logger.info(f"Certificate chain saved at: {chain_file}")
    except Exception as e:
        logger.error("Failed to rekey certificate")
        logger.error(e)
        logger.debug(traceback.format_exc())

def test_revoke_cert(client, cert_path, reason=0):
    """
    Revoke a certificate.
    """
    try:
        crypto_utils = CryptoUtils()
        # serial_number, issuer = crypto_utils.get_revocatione_details(cert_path)
        client.revocation(reason=reason, oldcert=cert_path)
        logger.info(f"Certificate {cert_path} successfully revoked for reason {reason}")
    except Exception as e:
        logger.error("Failed to revoke certificate")
        logger.error(e)
        logger.debug(traceback.format_exc())

def test_retrieve_ca_cert(client):
    """
    Retrieve CA certificates.
    """
    try:
        cert_file = client.getcacerts()
        logger.info(f"CA certificates retrieved and saved at: {cert_file}")
    except Exception as e:
        logger.error("Failed to retrieve CA certificates")
        logger.error(e)
        logger.debug(traceback.format_exc())


def test_retrieve_root_ca_cert(client):
    """
    Retrieve root CA certificates.
    """
    try:
        cert_file = client.getrootupdate(newwithnew="rootCa.pem")
        logger.info(f"CA certificates retrieved and saved at: {cert_file}")
    except Exception as e:
        logger.error("Failed to retrieve CA certificates")
        logger.error(e)
        logger.debug(traceback.format_exc())

# Usage example
if __name__ == "__main__":
    ca_server = "127.0.0.1:8000"
    domain = "plc"
    initialization_path = f"/.well-known/cmp/p/{domain}/initialization/mqtt_client/"
    #initialization_path = f"/.well-known/cmp/p/{domain}/initialization/"
    revocation_path = f"/.well-known/cmp/p/{domain}/revocation/"
    certification_path = f"/.well-known/cmp/p/{domain}/certification/"
    keyupdate_path = f"/.well-known/cmp/p/{domain}/keyupdate/"
    ca_cert_path = f"/.well-known/cmp/p/{domain}/getcacerts/"
    root_ca_cert_path = f"/.well-known/cmp/p/{domain}/getrootupdate/"

    cert = "./secret_trustpoint/cmp_client_cert.pem"
    key = "./secret_trustpoint/cmp_client_key.pem"
    trusted_cert_chain = "./secret_trustpoint/ca_cert.pem"

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

    #initialization_client = initialize_client(ca_server, initialization_path, cert, key, trusted_cert_chain)
    #test_initialization(initialization_client, dn_info, san_info)

    oldcert_key = "./bin/initialization_20240822160755/key.pem"
    certificate_to_be_updated = "./bin/initialization_20240822160755/cert.pem"

    #certification_client = initialize_client(ca_server, certification_path, cert=cert, key=key, trusted_cert_chain=trusted_cert_chain)
    #test_certification(certification_client, key_path="./bin/initialization_20240820220156/key.pem", old_cert=certificate_to_be_updated)

    #keyupdate_client = initialize_client(ca_server, keyupdate_path, cert=certificate_to_be_updated, key=oldcert_key, trusted_cert_chain=trusted_cert_chain)
    #test_key_update(keyupdate_client)

    revocation_client = initialize_client(ca_server, revocation_path, cert, key, trusted_cert_chain)
    test_revoke_cert(revocation_client, "./bin/initialization_20240820220156/cert.pem", reason=1)

    #get_ca_certs_client = initialize_client(ca_server, ca_cert_path, cert, key, trusted_cert_chain)
    #test_retrieve_ca_cert(get_ca_certs_client)

    #get_root_ca_certs_client = initialize_client(ca_server, root_ca_cert_path, cert, key, trusted_cert_chain)
    #test_retrieve_root_ca_cert(get_root_ca_certs_client)
