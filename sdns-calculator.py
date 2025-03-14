import sys
import hashlib
import base64
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Protocol ID mapping per DNSStamp specifications
PROTOCOL_IDS = {
    "DNSCrypt": 0x01,
    "DoH": 0x02,
    "DoT": 0x03,
    "DoQ": 0x04  # DNS over QUIC (speculative ID per draft)
}

def get_server_certificate(hostname, port, protocol):
    """Retrieve server certificate based on protocol type"""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    if protocol == "DoT":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('DEFAULT@SECLEVEL=2')

    with socket.create_connection((hostname, port)) as sock:
        if protocol in ["DoT", "DoH"]:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                cert_data = sslsock.getpeercert(binary_form=True)
        else:
            raise NotImplementedError("Certificate validation only supports DoH/DoT")
    return x509.load_der_x509_certificate(cert_data, default_backend())

def extract_tbs_certificate(cert):
    return cert.tbs_certificate_bytes

def generate_hash_segment(cert):
    tbs_data = extract_tbs_certificate(cert)
    return b'\x20' + hashlib.sha256(tbs_data).digest()

def build_dns_stamp(
    protocol_id,
    address,
    hostname,
    path,
    cert,
    dnssec=False,
    no_filter=False,
    no_logs=False
):
    """Construct DNSStamp with protocol extensions"""
    protocol = protocol_id.to_bytes(1, 'big')
    
    flags = 0
    if dnssec: flags |= 0x80  # DNSSEC validation required
    if no_filter: flags |= 0x40
    if no_logs: flags |= 0x20
    flags = flags.to_bytes(1, 'big')
    
    address_seg = bytes([len(address)]) + address.encode()
    hash_seg = generate_hash_segment(cert)
    hostname_seg = bytes([len(hostname)]) + hostname.encode()
    path_seg = bytes([len(path)]) + path.encode()
    
    full_bin = (
        protocol +          # 1-byte protocol ID
        flags +             # 1-byte flags (DNSSEC/NoFilter/NoLogs)
        b'\x00'*7 +         # Reserved bytes (total 8)
        address_seg +       # Address segment
        hash_seg +          # Certificate hash
        hostname_seg +      # Hostname segment
        path_seg            # Path segment
    )
    
    encoded = base64.urlsafe_b64encode(full_bin).decode().rstrip('=')
    return f"sdns://{encoded}"

if __name__ == "__main__":
    try:
        print("Protocol options:")
        for idx, (name, _) in enumerate(PROTOCOL_IDS.items(), 1):
            print(f"{idx}. {name}")
        protocol_choice = int(input("Enter protocol number: "))
        protocol = list(PROTOCOL_IDS.keys())[protocol_choice-1]
        protocol_id = PROTOCOL_IDS[protocol]
        
        address = input("Server address (IPv4/IPv6/domain): ")
        hostname = input("Hostname for certificate validation: ")
        path = input("API path (e.g. /dns-query): ")
        port = int(input(f"Port (default {853 if protocol == 'DoT' else 443}): ") or 
                  (853 if protocol == 'DoT' else 443))
        
        print(f"Retrieving certificate from {hostname}:{port}...")
        cert = get_server_certificate(hostname, port, protocol)
        
        dnssec = input("Enable DNSSEC validation? (y/n): ").lower() == 'y'
        no_filter = input("Declare no filtering? (y/n): ").lower() == 'y'
        no_logs = input("Declare no logs? (y/n): ").lower() == 'y'
        
        stamp = build_dns_stamp(
            protocol_id,
            address,
            hostname,
            path,
            cert,
            dnssec=dnssec,
            no_filter=no_filter,
            no_logs=no_logs
        )
        print("\nGenerated DNSStamp:")
        print(stamp)
        
    except ssl.SSLError as e:
        print(f"Certificate validation failed: {e}")
    except x509.InvalidCertificateError as e:
        print(f"Invalid certificate: {e}")
    except socket.gaierror:
        print("Failed to resolve server address")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"Connection failed: {e}")
    except Exception as e:
        print(f"Error: {e}")
