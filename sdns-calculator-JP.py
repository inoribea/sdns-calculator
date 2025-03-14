import sys
import hashlib
import base64
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# プロトコルIDのマッピング（DNSStamp仕様に基づく）
PROTOCOL_IDS = {
    "DNSCrypt": 0x01,
    "DoH": 0x02,
    "DoT": 0x03,
    "DoQ": 0x04  # DNS over QUIC（草案に基づくID）
}

def get_server_certificate(hostname, port, protocol):
    """プロトコルに応じたサーバー証明書の取得"""
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
            raise NotImplementedError("証明書検証はDoH/DoTのみ対応")
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
    """DNSStampの生成（拡張フラグ含む）"""
    protocol = protocol_id.to_bytes(1, 'big')
    
    flags = 0
    if dnssec: flags |= 0x80  # DNSSEC検証必須
    if no_filter: flags |= 0x40
    if no_logs: flags |= 0x20
    flags = flags.to_bytes(1, 'big')
    
    address_seg = bytes([len(address)]) + address.encode()
    hash_seg = generate_hash_segment(cert)
    hostname_seg = bytes([len(hostname)]) + hostname.encode()
    path_seg = bytes([len(path)]) + path.encode()
    
    full_bin = (
        protocol +          # 1バイト：プロトコルID
        flags +             # 1バイト：フラグ（DNSSEC/NoFilter/NoLogs）
        b'\x00'*7 +         # 予約領域（合計8バイト）
        address_seg +       # アドレスセグメント
        hash_seg +          # 証明書ハッシュ
        hostname_seg +      # ホスト名セグメント
        path_seg            # パスセグメント
    )
    
    encoded = base64.urlsafe_b64encode(full_bin).decode().rstrip('=')
    return f"sdns://{encoded}"

if __name__ == "__main__":
    try:
        print("プロトコル オプション:")
        for idx, (name, _) in enumerate(PROTOCOL_IDS.items(), 1):
            print(f"{idx}. {name}")
        protocol_choice = int(input("プロトコル番号を入力してください： "))
        protocol = list(PROTOCOL_IDS.keys())[protocol_choice-1]
        protocol_id = PROTOCOL_IDS[protocol]
        
        address = input("サーバー アドレス（IPv4/IPv6/ドメイン）: ")
        hostname = input("証明書検証用ホスト名： ")
        path = input("APIパス（例：/dns-query）: ")
        port = int(input(f"ポート（デフォルト {853 if protocol == 'DoT' else 443}）: ") or 
                  (853 if protocol == 'DoT' else 443))
        
        print(f"{hostname}:{port} の証明書を取得中...")
        cert = get_server_certificate(hostname, port, protocol)
        
        dnssec = input("DNSSEC検証を有効にする？ (y/n): ").lower() == 'y'
        no_filter = input("フィルタなしを宣言？ (y/n): ").lower() == 'y'
        no_logs = input("ログなしを宣言？ (y/n): ").lower() == 'y'
        
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
        print("\n生成されたDNSStamp：")
        print(stamp)
        
    except ssl.SSLError as e:
        print(f"証明書検証に失敗しました：{e}")
    except x509.InvalidCertificateError as e:
        print(f"無効な証明書：{e}")
    except socket.gaierror:
        print("サーバー アドレスの解決に失敗しました")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"接続エラー：{e}")
    except Exception as e:
        print(f"エラー：{e}")
