import base64
import socket
import Encryption as e
import os

# 创建客户端套接字
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_host = "127.0.0.1"
server_port = 8080
client_socket.connect((server_host, server_port))

# asymmetric encryption
# request public key of server
http_request1 = "GET /?Encryption=1 HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAuthorization: Basic Y2xpZW50MToxMjM=\r\n\r\n".format(server_host)
private_key, public_key = e.generate_keys()
client_socket.sendall(http_request1.encode('utf-8'))
response = client_socket.recv(4096).decode('utf-8')
headers = response.split('\r\n\r\n', 1)[0].split('\r\n')
for header in headers:
    if header.startswith('Content-Length: '):
        content_length = int(header.split('Content-Length: ')[1])
        break
while len(response) < content_length:
    response += client_socket.recv(4096).decode('utf-8')

print("response1: ", response)

received_key = response.split('\r\n\r\n', 1)[1]

# send encrypted_symmetric_key
symmetric_key = os.urandom(32)
encrypted_symmetric_key = e.encrypt_with_public_key(received_key.encode('utf-8'), symmetric_key)
http_request2_header = "POST /sendkey HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAuthorization: Basic Y2xpZW50MToxMjM=\r\nContent-Length: {}\r\n\r\n".format(server_host, len(encrypted_symmetric_key))
client_socket.sendall((http_request2_header + encrypted_symmetric_key).encode('utf-8'))
response = client_socket.recv(4096).decode('utf-8')

header, body = response.split('\r\n\r\n', 1)
headers = header.split('\r\n')
for h in headers:
    if h.startswith('Content-Length: '):
        content_length = int(h.split('Content-Length: ')[1])
        break
while len(body) < content_length:
    body += client_socket.recv(4096).decode('utf-8')

print("response2", response + body)


# communication with symmetric encryption
password = 'Basic Y2xpZW50MToxMjM='
en_password = e.symmetric_encrypt(symmetric_key, password.encode('utf-8'))

message = 'HELLO'
en_message = e.symmetric_encrypt(symmetric_key, message.encode('utf-8'))

http_request3_header = "POST / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: {}\r\nContent-Length: {}\r\nEncryption: enable\r\n\r\n".format(server_host, en_password, len(en_message))
client_socket.sendall((http_request3_header+ en_message).encode('utf-8'))

response = client_socket.recv(4096).decode('utf-8')
print("response3: ", response)


client_socket.close()
