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
    "DoQ": 0x04
}

ADDITIONAL_OPTION = "Certificate Info"

def get_server_certificate(hostname, port, protocol):
    """Retrieve server certificate based on protocol type"""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    if protocol.lower() == "dot":
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        with socket.create_connection((hostname, port)) as sock:
            if protocol.lower() in ["dot", "doh"]:
                with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                    cert_data = sslsock.getpeercert(binary_form=True)
            else:
                print("Error: Certificate validation only supports DoH/DoT.")
                return None
        return x509.load_der_x509_certificate(cert_data, default_backend())
    except ssl.SSLError as e:
        print(f"Certificate validation failed: {e}")
        return None
    except socket.gaierror:
        print("Failed to resolve server address.")
        return None
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"Connection failed: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

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
    cert=None, # Make cert optional
    dnssec=False,
    no_filter=False,
    no_logs=False
):
    """Construct DNSStamp with protocol extensions"""
    protocol = protocol_id.to_bytes(1, 'big')
    
    flags = 0
    if dnssec: flags |= 0x80
    if no_filter: flags |= 0x40
    if no_logs: flags |= 0x20
    flags = flags.to_bytes(1, 'big')
    
    address_seg = bytes([len(address)]) + address.encode()
    
    # Determine hash_seg based on protocol_id
    if protocol_id == PROTOCOL_IDS["DNSCrypt"]:
        hash_seg = b'\x00' * 8 # DNSCrypt uses 8 null bytes for hash
    elif cert:
        hash_seg = generate_hash_segment(cert)
    else:
        # This case should ideally not be reached if logic is correct,
        # but as a fallback, use empty hash or raise an error.
        # For now, let's use 8 null bytes as a safe default for protocols requiring cert but not provided.
        hash_seg = b'\x00' * 8 
        print("Warning: Certificate not provided, but protocol might require it. Using empty hash.")
    
    hostname_seg = bytes([len(hostname)]) + hostname.encode()
    path_seg = bytes([len(path)]) + path.encode()
    
    full_bin = (
        protocol +
        flags +
        b'\x00'*7 + # Reserved bytes
        address_seg +
        hash_seg +
        hostname_seg +
        path_seg
    )
    
    encoded = base64.urlsafe_b64encode(full_bin).decode().rstrip('=')
    return f"sdns://{encoded}"

def display_certificate_information(hostname, port, protocol_type):
    """Helper function to display certificate information"""
    try:
        print(f"Retrieving certificate from {hostname}:{port} for {protocol_type}...")
        cert = get_server_certificate(hostname, port, protocol_type)
        print("\n--- Server Certificate Information ---")
        print(f"Subject: {cert.subject}")
        print(f"Issuer: {cert.issuer}")
        print(f"Serial Number: {cert.serial_number}")
        print(f"Valid From (UTC): {cert.not_valid_before_utc}")
        print(f"Valid Until (UTC): {cert.not_valid_after_utc}")
        
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        sha256_fingerprint = hashlib.sha256(cert_der).hexdigest()
        print(f"SHA256 Fingerprint: {sha256_fingerprint}")
        
        tbs_data = extract_tbs_certificate(cert)
        tbs_sha256_hash = hashlib.sha256(tbs_data).hexdigest()
        print(f"TBS SHA256 Hash (for DNSStamp): {tbs_sha256_hash}")
        print("--------------------------------------\n")
    except ssl.SSLError as e:
        print(f"Certificate validation failed: {e}")
    except socket.gaierror:
        print("Failed to resolve server address")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"Connection failed: {e}")
    except NotImplementedError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    try:
        print("Protocol options:")
        all_options = list(PROTOCOL_IDS.keys()) + [ADDITIONAL_OPTION]
        for idx, name in enumerate(all_options, 1):
            print(f"{idx}. {name}")
        
        protocol_choice_input = input("Enter option number (eg: 2 for DoH, 5 for Certificate Info): ")
        protocol_choice = int(protocol_choice_input) if protocol_choice_input else 2
        
        if not (1 <= protocol_choice <= len(all_options)):
            print("Invalid option number. Exiting.")
            sys.exit(1)
            
        selected_option_name = all_options[protocol_choice-1]

        if selected_option_name == ADDITIONAL_OPTION:
            print(f"\n--- {ADDITIONAL_OPTION} ---")
            hostname_input = input("Enter hostname for certificate validation (eg: cloudflare-dns.com): ")
            if not hostname_input:
                hostname_input = "cloudflare-dns.com"
                print(f"Hostname not provided, using default: {hostname_input}")
            
            port_input = input("Enter port (eg: 853 for DoT, 443 for DoH): ")
            port = int(port_input) if port_input else 443
            
            protocol_type_input = input("Enter protocol type for certificate retrieval (DoH/DoT): ").strip()
            if protocol_type_input.lower() not in ["doh", "dot"]:
                print("Invalid protocol type. Only DoH or DoT supported for certificate retrieval. Exiting.")
                sys.exit(1)

            display_certificate_information(hostname_input, port, protocol_type_input.lower())
            sys.exit(0)
        else:
            protocol = selected_option_name
            protocol_id = PROTOCOL_IDS[protocol]
            
            if protocol == "DNSCrypt":
                default_address = "208.67.222.222" # Example for Cloudflare DNSCrypt
                default_hostname = "dnscrypt.cloudflare-dns.com"
                default_path = "" # DNSCrypt typically doesn't use a path
                default_port = 443 # DNSCrypt typically uses port 443
            elif protocol == "DoH":
                default_address = "cloudflare-dns.com"
                default_hostname = "cloudflare-dns.com"
                default_path = "/dns-query"
                default_port = 443
            elif protocol == "DoT":
                default_address = "cloudflare-dns.com"
                default_hostname = "cloudflare-dns.com"
                default_path = ""
                default_port = 853
            elif protocol == "DoQ":
                default_address = "cloudflare-dns.com"
                default_hostname = "cloudflare-dns.com"
                default_path = ""
                default_port = 853 # DoQ typically uses port 853
            else: # Fallback for other protocols or new ones
                default_address = "cloudflare-dns.com"
                default_hostname = "cloudflare-dns.com"
                default_path = ""
                default_port = 443

            address_input = input(f"Server address (IPv4/IPv6/domain) (eg: {default_address}): ")
            address = address_input if address_input else default_address
            
            hostname_input = input(f"Hostname for certificate validation (eg: {default_hostname}): ")
            hostname = hostname_input if hostname_input else default_hostname
            
            path_input = input(f"API path (eg: /dns-query) (default: {default_path}): ")
            path = path_input if path_input else default_path
            
            port_input = input(f"Port (default: {default_port}): ")
            port = int(port_input) if port_input else default_port
            
            cert = None
            if protocol.lower() in ["doh", "dot"]:
                print(f"Retrieving certificate from {hostname}:{port}...")
                cert = get_server_certificate(hostname, port, protocol)
                if cert is None:
                    print("Error: Failed to retrieve certificate. Cannot generate DNSStamp.")
                    sys.exit(1)
            else:
                print(f"Skipping certificate retrieval for {protocol} protocol.")
            
            dnssec_input = input("Enable DNSSEC validation? (y/n) (default: n): ").lower()
            dnssec = dnssec_input == 'y'
            
            no_filter_input = input("Declare no filtering? (y/n) (default: n): ").lower()
            no_filter = no_filter_input == 'y'
            
            no_logs_input = input("Declare no logs? (y/n) (default: n): ").lower()
            no_logs = no_logs_input == 'y'
            
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
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Exiting.")
        sys.exit(0)
    except ssl.SSLError as e:
        print(f"Certificate validation failed: {e}")
    except socket.gaierror:
        print("Failed to resolve server address")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"Connection failed: {e}")
    except Exception as e:
        print(f"Error: {e}")
