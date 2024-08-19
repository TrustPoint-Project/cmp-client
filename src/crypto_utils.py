from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import Name, NameAttribute, DNSName, IPAddress, CertificateSigningRequestBuilder, SubjectAlternativeName, UniformResourceIdentifier
from cryptography.x509.oid import NameOID
import ipaddress

class CryptoUtils:
    def __init__(self):
        """
        Initialize the CryptoUtils class.
        """
        pass

    def get_revocatione_details(self, cert_path):
        """
        Load a PEM-encoded X.509 certificate and extract its serial number and issuer.

        :param cert_path: The path to the certificate file.
        :return: A tuple containing the serial number and the issuer in string format.
        """
        with open(cert_path, "rb") as cert_file:
            cert_data = cert_file.read()
            cert_load = load_pem_x509_certificate(cert_data, default_backend())
            serial_number = cert_load.serial_number
            issuer = f"/{cert_load.issuer.rfc4514_string()}"
        return serial_number, issuer
    def generate_key(self, target_dir, key_algorithm, key_size=None, curve=None):
        """
        Generate a private key.

        :param target_dir: The directory to store the key.
        :param key_algorithm: The key algorithm ('RSA' or 'ECC').
        :param key_size: The size of the RSA key (optional).
        :param curve: The ECC curve (optional).
        :return: The path to the key file and the private key object.
        """
        key_path = target_dir / "key.pem"
        if key_algorithm == 'RSA':
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        elif key_algorithm == 'ECC':
            private_key = ec.generate_private_key(curve)
        else:
            raise ValueError("Unsupported key algorithm. Use 'RSA' or 'ECC'.")

        key_path.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        return key_path, private_key

    def load_private_key(self, key_path, password=None):
        """
        Load a private key from a file.

        :param key_path: The path to the key file.
        :param password: The password for the key file (optional).
        :return: The private key object.
        """
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode() if password else None
            )
        return private_key

    def generate_csr(self, target_dir, dn_info, san_info, private_key):
        """
        Generate a Certificate Signing Request (CSR).

        :param target_dir: The directory to store the CSR.
        :param dn_info: The distinguished name information.
        :param san_info: The subject alternative name information.
        :param private_key: The private key to sign the CSR.
        :return: The path to the CSR file.
        """
        csr_file = target_dir / "csr.pem"
        name_attributes = [NameAttribute(NameOID.COMMON_NAME, dn_info['CN'])]

        if 'C' in dn_info:
            name_attributes.append(NameAttribute(NameOID.COUNTRY_NAME, dn_info['C']))
        if 'ST' in dn_info:
            name_attributes.append(NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, dn_info['ST']))
        if 'L' in dn_info:
            name_attributes.append(NameAttribute(NameOID.LOCALITY_NAME, dn_info['L']))
        if 'O' in dn_info:
            name_attributes.append(NameAttribute(NameOID.ORGANIZATION_NAME, dn_info['O']))
        if 'OU' in dn_info:
            name_attributes.append(NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, dn_info['OU']))
        if 'emailAddress' in dn_info:
            name_attributes.append(NameAttribute(NameOID.EMAIL_ADDRESS, dn_info['emailAddress']))

        csr_builder = CertificateSigningRequestBuilder().subject_name(Name(name_attributes))

        san_list = []
        if 'DNS' in san_info:
            san_list.extend(DNSName(dns) for dns in san_info['DNS'])
        if 'IP' in san_info:
            san_list.extend(IPAddress(ipaddress.ip_address(ip)) for ip in san_info['IP'])
        if 'URI' in san_info:
            san_list.extend(UniformResourceIdentifier(uri) for uri in san_info['URI'])

        if san_list:
            csr_builder = csr_builder.add_extension(SubjectAlternativeName(san_list), critical=False)

        csr = csr_builder.sign(private_key, hashes.SHA256())
        csr_file.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        return csr_file