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

ADDITIONAL_OPTION = "証明書情報"

def get_server_certificate(hostname, port, protocol):
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
                print("エラー: 証明書の検証は DoH/DoT のみをサポートしています。")
                return None
        return x509.load_der_x509_certificate(cert_data, default_backend())
    except ssl.SSLError as e:
        print(f"証明書の検証に失敗しました: {e}")
        return None
    except socket.gaierror:
        print("サーバーアドレスの解決に失敗しました。")
        return None
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"接続に失敗しました: {e}")
        return None
    except Exception as e:
        print(f"予期せぬエラーが発生しました: {e}")
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
        print("警告: 证书未提供，但协议可能需要。使用空哈希。")
    
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
    try:
        print(f"{hostname}:{port} から証明書を取得中...")
        cert = get_server_certificate(hostname, port, protocol_type)
        print("\n--- サーバー証明書情報 ---")
        print(f"サブジェクト: {cert.subject}")
        print(f"発行者: {cert.issuer}")
        print(f"シリアル番号: {cert.serial_number}")
        print(f"有効期間開始 (UTC): {cert.not_valid_before_utc}")
        print(f"有効期間終了 (UTC): {cert.not_valid_after_utc}")
        
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        sha256_fingerprint = hashlib.sha256(cert_der).hexdigest()
        print(f"SHA256 フィンガープリント: {sha256_fingerprint}")
        
        tbs_data = extract_tbs_certificate(cert)
        tbs_sha256_hash = hashlib.sha256(tbs_data).hexdigest()
        print(f"TBS SHA256 ハッシュ (DNSStamp 用): {tbs_sha256_hash}")
        print("--------------------------------------\n")
    except ssl.SSLError as e:
        print(f"証明書の検証に失敗しました: {e}")
    except socket.gaierror:
        print("サーバーアドレスの解決に失敗しました")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"接続に失敗しました: {e}")
    except NotImplementedError as e:
        print(f"エラー: {e}")
    except Exception as e:
        print(f"予期せぬエラーが発生しました: {e}")

if __name__ == "__main__":
    try:
        print("プロトコルオプション:")
        all_options = list(PROTOCOL_IDS.keys()) + [ADDITIONAL_OPTION]
        for idx, name in enumerate(all_options, 1):
            print(f"{idx}. {name}")
        
        protocol_choice_input = input("オプション番号を入力してください (例: DoH は 2, 証明書情報は 5): ")
        protocol_choice = int(protocol_choice_input) if protocol_choice_input else 2
        
        if not (1 <= protocol_choice <= len(all_options)):
            print("無効なオプション番号です。終了します。")
            sys.exit(1)
            
        selected_option_name = all_options[protocol_choice-1]

        if selected_option_name == ADDITIONAL_OPTION:
            print(f"\n--- {ADDITIONAL_OPTION} ---")
            hostname_input = input("証明書検証用のホスト名を入力してください (例: cloudflare-dns.com): ")
            if not hostname_input:
                hostname_input = "cloudflare-dns.com"
                print(f"ホスト名が指定されていません。デフォルトを使用します: {hostname_input}")
            
            port_input = input("ポートを入力してください (例: DoT は 853, DoH は 443): ")
            port = int(port_input) if port_input else 443
            
            protocol_type_input = input("証明書取得用のプロトコルタイプを入力してください (DoH/DoT): ").strip()
            if protocol_type_input.lower() not in ["doh", "dot"]:
                print("無効なプロトコルタイプです。証明書取得は DoH/DoT のみサポートされています。終了します。")
                sys.exit(1)

            display_certificate_information(hostname_input, port, protocol_type_input.lower())
            sys.exit(0)
        else:
            protocol = selected_option_name
            protocol_id = PROTOCOL_IDS[protocol]
            
            if protocol == "DNSCrypt":
                default_address = "208.67.222.222" # Cloudflare DNSCrypt の例
                default_hostname = "dnscrypt.cloudflare-dns.com"
                default_path = "" # DNSCrypt は通常パスを使用しません
                default_port = 443 # DNSCrypt は通常ポート 443 を使用します
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
                default_port = 853 # DoQ は通常ポート 853 を使用します
            else: # その他のプロトコルまたは新しいプロトコルのフォールバック
                default_address = "cloudflare-dns.com"
                default_hostname = "cloudflare-dns.com"
                default_path = ""
                default_port = 443

            address_input = input(f"サーバーアドレス (IPv4/IPv6/ドメイン) (例: {default_address}): ")
            address = address_input if address_input else default_address
            
            hostname_input = input(f"証明書検証用のホスト名を入力してください (例: {default_hostname}): ")
            hostname = hostname_input if hostname_input else default_hostname
            
            path_input = input(f"API パス (例: /dns-query) (デフォルト: {default_path}): ")
            path = path_input if path_input else default_path
            
            port_input = input(f"ポート (デフォルト: {default_port}): ")
            port = int(port_input) if port_input else default_port
            
            cert = None
            if protocol.lower() in ["doh", "dot"]:
                print(f"{hostname}:{port} から証明書を取得中...")
                cert = get_server_certificate(hostname, port, protocol)
                if cert is None:
                    print("エラー: 証明書の取得に失敗しました。DNSStamp を生成できません。")
                    sys.exit(1)
            else:
                print(f"{protocol} プロトコルの証明書取得をスキップします。")
            
            dnssec_input = input("DNSSEC 検証を有効にしますか? (y/n) (デフォルト: n): ").lower()
            dnssec = dnssec_input == 'y'
            
            no_filter_input = input("フィルタリングなしを宣言しますか? (y/n) (デフォルト: n): ").lower()
            no_filter = no_filter_input == 'y'
            
            no_logs_input = input("ログなしを宣言しますか? (y/n) (デフォルト: n): ").lower()
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
            print("\n生成された DNSStamp:")
            print(stamp)
            
    except KeyboardInterrupt:
        print("\n操作はユーザーによってキャンセルされました。終了します。")
        sys.exit(0)
    except ssl.SSLError as e:
        print(f"証明書の検証に失敗しました: {e}")
    except socket.gaierror:
        print("サーバーアドレスの解決に失敗しました")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"接続に失敗しました: {e}")
    except Exception as e:
        print(f"エラー: {e}")
