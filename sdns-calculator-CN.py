import sys
import hashlib
import base64
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

PROTOCOL_IDS = {
    "DNSCrypt": 0x01,
    "DoH": 0x02,
    "DoT": 0x03,
    "DoQ": 0x04
}

ADDITIONAL_OPTION = "证书信息"

def get_server_certificate(hostname, port, protocol):
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    if protocol.lower() == "dot":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('DEFAULT@SECLEVEL=2')

    with socket.create_connection((hostname, port)) as sock:
        if protocol.lower() in ["dot", "doh"]:
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
    protocol = protocol_id.to_bytes(1, 'big')
    
    flags = 0
    if dnssec: flags |= 0x80
    if no_filter: flags |= 0x40
    if no_logs: flags |= 0x20
    flags = flags.to_bytes(1, 'big')
    
    address_seg = bytes([len(address)]) + address.encode()
    hash_seg = generate_hash_segment(cert)
    hostname_seg = bytes([len(hostname)]) + hostname.encode()
    path_seg = bytes([len(path)]) + path.encode()
    
    full_bin = (
        protocol +
        flags +
        b'\x00'*7 +
        address_seg +
        hash_seg +
        hostname_seg +
        path_seg
    )
    
    encoded = base64.urlsafe_b64encode(full_bin).decode().rstrip('=')
    return f"sdns://{encoded}"

def display_certificate_information(hostname, port, protocol_type):
    try:
        print(f"正在从 {hostname}:{port} 检索证书...")
        cert = get_server_certificate(hostname, port, protocol_type)
        print("\n--- 服务器证书信息 ---")
        print(f"主题: {cert.subject}")
        print(f"颁发者: {cert.issuer}")
        print(f"序列号: {cert.serial_number}")
        print(f"有效期从 (UTC): {cert.not_valid_before_utc}")
        print(f"有效期至 (UTC): {cert.not_valid_after_utc}")
        
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        sha256_fingerprint = hashlib.sha256(cert_der).hexdigest()
        print(f"SHA256 指纹: {sha256_fingerprint}")
        
        tbs_data = extract_tbs_certificate(cert)
        tbs_sha256_hash = hashlib.sha256(tbs_data).hexdigest()
        print(f"TBS SHA256 哈希 (用于 DNSStamp): {tbs_sha256_hash}")
        print("--------------------------------------\n")
    except ssl.SSLError as e:
        print(f"证书验证失败: {e}")
    except socket.gaierror:
        print("无法解析服务器地址")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"连接失败: {e}")
    except NotImplementedError as e:
        print(f"错误: {e}")
    except Exception as e:
        print(f"发生意外错误: {e}")

if __name__ == "__main__":
    try:
        print("协议选项:")
        all_options = list(PROTOCOL_IDS.keys()) + [ADDITIONAL_OPTION]
        for idx, name in enumerate(all_options, 1):
            print(f"{idx}. {name}")
        
        protocol_choice_input = input("输入选项编号 (例如: DoH 输入 2, 证书信息输入 5): ")
        protocol_choice = int(protocol_choice_input) if protocol_choice_input else 2
        
        if not (1 <= protocol_choice <= len(all_options)):
            print("无效的选项编号。正在退出。")
            sys.exit(1)
            
        selected_option_name = all_options[protocol_choice-1]

        if selected_option_name == ADDITIONAL_OPTION:
            print(f"\n--- {ADDITIONAL_OPTION} ---")
            hostname_input = input("输入用于证书验证的主机名 (例如: cloudflare-dns.com): ")
            if not hostname_input:
                hostname_input = "cloudflare-dns.com"
                print(f"未提供主机名，使用默认值: {hostname_input}")
            
            port_input = input("输入端口 (例如: DoT 为 853, DoH 为 443): ")
            port = int(port_input) if port_input else 443
            
            protocol_type_input = input("输入用于证书检索的协议类型 (DoH/DoT): ").strip()
            if protocol_type_input.lower() not in ["doh", "dot"]:
                print("无效的协议类型。证书检索仅支持 DoH/DoT。正在退出。")
                sys.exit(1)

            display_certificate_information(hostname_input, port, protocol_type_input.lower())
            sys.exit(0)
        else:
            protocol = selected_option_name
            protocol_id = PROTOCOL_IDS[protocol]
            
            default_address = "cloudflare-dns.com"
            address_input = input(f"服务器地址 (IPv4/IPv6/域名) (例如: {default_address}): ")
            address = address_input if address_input else default_address
            
            default_hostname = address
            hostname_input = input(f"用于证书验证的主机名 (例如: {default_hostname}): ")
            hostname = hostname_input if hostname_input else default_hostname
            
            default_path = "/dns-query" if protocol == "DoH" else ""
            path_input = input(f"API 路径 (例如: /dns-query) (默认: {default_path}): ")
            path = path_input if path_input else default_path
            
            default_port = 853 if protocol == 'DoT' else 443
            port_input = input(f"端口 (默认: {default_port}): ")
            port = int(port_input) if port_input else default_port
            
            print(f"正在从 {hostname}:{port} 检索证书...")
            cert = get_server_certificate(hostname, port, protocol)
            
            dnssec_input = input("启用 DNSSEC 验证? (y/n) (默认: n): ").lower()
            dnssec = dnssec_input == 'y'
            
            no_filter_input = input("声明不进行过滤? (y/n) (默认: n): ").lower()
            no_filter = no_filter_input == 'y'
            
            no_logs_input = input("声明不记录日志? (y/n) (默认: n): ").lower()
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
            print("\n生成的 DNSStamp:")
            print(stamp)
            
    except KeyboardInterrupt:
        print("\n操作已取消。正在退出。")
        sys.exit(0)
    except ssl.SSLError as e:
        print(f"证书验证失败: {e}")
    except socket.gaierror:
        print("无法解析服务器地址")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"连接失败: {e}")
    except Exception as e:
        print(f"错误: {e}")
