import sys
import hashlib
import base64
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 协议ID映射表（参考DNSStamp规范）
PROTOCOL_IDS = {
    "DNSCrypt": 0x01,  # DNSCrypt
    "DoH": 0x02,    # DNS over HTTPS
    "DoT": 0x03,    # DNS over TLS
    "DoQ": 0x04     # DNS over QUIC（假设ID为0x04，需确认实际规范）
}

def get_server_certificate(hostname, port, protocol):
    """根据协议类型安全获取服务器证书"""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    if protocol == "DoT":
        # DNS-over-TLS需要显式设置协议版本
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('DEFAULT@SECLEVEL=2')

    with socket.create_connection((hostname, port)) as sock:
        if protocol in ["DoT", "DoH"]:
            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as sslsock:
                cert_data = sslsock.getpeercert(binary_form=True)
        else:
            # DoQ等其他协议暂不支持证书获取（需额外处理）
            raise NotImplementedError("仅支持DoH/DoT协议的证书验证")
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
    """构建完整的DNS Stamp（含扩展标志）"""
    protocol = protocol_id.to_bytes(1, 'big')
    
    # 构建扩展标志（参考规范）
    flags = 0
    if dnssec: flags |= 0x80  # DNSSEC强制验证
    if no_filter: flags |= 0x40
    if no_logs: flags |= 0x20
    flags = flags.to_bytes(1, 'big')
    
    address_bytes = address.encode('ascii')
    address_seg = bytes([len(address_bytes)]) + address_bytes
    
    hash_seg = generate_hash_segment(cert)
    
    hostname_bytes = hostname.encode('ascii')
    hostname_seg = bytes([len(hostname_bytes)]) + hostname_bytes
    
    path_bytes = path.encode('ascii')
    path_seg = bytes([len(path_bytes)]) + path_bytes
    
    # 构建最终字节流（规范顺序）
    full_bin = (
        protocol +          # 1字节：协议ID
        flags +             # 1字节：扩展标志（DNSSEC/NoFilter/NoLogs）
        b'\x00'*7 +         # 剩余保留字段（共8字节）
        address_seg +       # 地址段
        hash_seg +          # 哈希段
        hostname_seg +      # 主机名段
        path_seg            # 路径段
    )
    
    encoded = base64.urlsafe_b64encode(full_bin).decode('utf-8').rstrip('=')
    return f"sdns://{encoded}"

if __name__ == "__main__":
    try:
        print("请选择协议类型：")
        for idx, (name, _) in enumerate(PROTOCOL_IDS.items(), 1):
            print(f"{idx}. {name}")
        protocol_choice = int(input("输入序号选择协议："))
        protocol = list(PROTOCOL_IDS.keys())[protocol_choice-1]
        protocol_id = PROTOCOL_IDS[protocol]
        
        address = input("服务器地址（IPv4/IPv6/域名）: ")
        hostname = input("证书验证域名（必须与证书匹配）: ")
        path = input("API路径（例如：/dns-query）: ")
        port = int(input(f"端口（默认{853 if protocol == 'DoT' else 443}）: ") or (853 if protocol == 'DoT' else 443))
        
        # 获取证书（DoT/DoH支持）
        print(f"正在获取{hostname}:{port}的证书...")
        cert = get_server_certificate(hostname, port, protocol)
        
        # 附加选项
        dnssec = input("是否强制DNSSEC验证？(y/n): ").lower() == 'y'
        no_filter = input("是否声明无过滤？(y/n): ").lower() == 'y'
        no_logs = input("是否声明无日志？(y/n): ").lower() == 'y'
        
        # 生成Stamp
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
        print("\n生成的DNS Stamp：")
        print(stamp)
        
    except ssl.SSLError as e:
        print(f"证书验证失败：{str(e)}")
    except x509.InvalidCertificateError as e:
        print(f"无效证书：{str(e)}")
    except socket.gaierror:
        print("无法解析服务器地址")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"连接失败：{str(e)}")
    except Exception as e:
        print(f"未知错误：{str(e)}")
