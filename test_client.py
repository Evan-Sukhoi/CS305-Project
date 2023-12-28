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
# print(response)
received_key = response.split('\r\n\r\n', 1)[1]

# send encrypted_symmetric_key
symmetric_key = os.urandom(32)
# b'mQ\x10\xf3#*\xa6\xbc\x9d\xc5\x15g\xc1\x8e&\xfa\xe5C\x01+?\x18\xc0pD\x08\xc1\x04\xa2q\xf94'
# print(received_key)
# b'\xa8\xd0\xa3H*\x84j|\x8d\x92V\xbf\x8f\x86\x86R2-\x1a\xaeNZI\x83\x9f<H\xaaN\xe5C\xf3'
encrypted_symmetric_key = e.encrypt_with_public_key(received_key.encode('utf-8'), symmetric_key)
http_request2_header = "POST /sendkey HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAuthorization: Basic Y2xpZW50MToxMjM=\r\nContent-Length: {}\r\n\r\n".format(server_host, len(encrypted_symmetric_key))
# print(encrypted_symmetric_key)
client_socket.sendall((http_request2_header + encrypted_symmetric_key).encode('utf-8'))
response = client_socket.recv(4096).decode('utf-8')

# communication with symmetric encryption
password = 'Basic Y2xpZW50MToxMjM='
en_password = e.symmetric_encrypt(symmetric_key, password.encode('utf-8'))
print(type(en_password))
print(e.symmetric_decrypt(symmetric_key, base64.b64decode(en_password)).decode('utf-8'))


message = 'HELLO'
en_message = e.symmetric_encrypt(symmetric_key, message.encode('utf-8'))
print(type(en_message))
print(e.symmetric_decrypt(symmetric_key, base64.b64decode(en_message)).decode('utf-8'))


print(en_password)
print(en_message)
http_request3_header = "POST /upload?path=/client1/ HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: {}\r\nContent-Length: {}\r\nEncryption: enable\r\n\r\n".format(server_host, en_password, len(en_message))
client_socket.sendall((http_request3_header+ en_message).encode('utf-8'))

# close
# http_request_final = "GET /?Encryption=1 HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAuthorization: Basic Y2xpZW50MToxMjM=\r\n\r\n".format(server_host)
# client_socket.sendall(http_request_final.encode('utf-8'))
# response = client_socket.recv(4096).decode('utf-8')