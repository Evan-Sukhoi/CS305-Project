import socket
import Encryption as e
import os
def send_http_request(host, port, request):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(request.encode())
        response = s.recv(4096).decode()
        response = response.split('\r\n\r\n', 1)[1]
    return response

# 请替换为实际的服务器地址和端口
server_host = "127.0.0.1"
server_port = 8080

# 构建一个简单的 HTTP GET 请求
http_request1 = """GET / HTTP/1.1
Host: {}
""".format(server_host)

private_key, public_key = e.generate_keys()

# 发送请求并获取响应
received_key = send_http_request(server_host, server_port, http_request1)
symmetric_key = os.urandom(32)
encrypted_symmetric_key = e.encrypt_with_public_key(received_key, symmetric_key)

http_request2 = """GET / HTTP/1.1
Host: {}
""".format(server_host)

response = send_http_request(server_host, server_port, http_request1)
