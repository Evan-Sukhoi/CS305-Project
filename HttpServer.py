'''
can only use the python libraries including {argparse socket
mimetypes io sys time datetime os signal threading pathlib traceback json}
'''

import socket
import argparse
import mimetypes
import io
import sys
import time
import datetime
import os
import signal
import threading
import pathlib
import traceback
import json
import base64

# other module can be used according to https://github.com/Leosang-lx/SUSTech-CS305-2023Fall
import re


class ClientAccount:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.base64 = self.getBase64()

    def getBase64(self):
        return base64.b64encode('{}:{}'.format(self.username, self.password).encode('utf-8')).decode('utf-8')


clients = [ClientAccount('client1', '123'),
           ClientAccount('client2', '123'),
           ClientAccount('client3', '123')]


class HttpServer:
    def __init__(self, client_socket, addr):
        self.client_socket = client_socket
        self.addr = addr

    def start(self):
        try:
            self.handle_request()
        except Exception as e:
            print('Exception: {}'.format(e))
            traceback.print_exc()
        finally:
            self.client_socket.close()

    def handle_request(self):
        # while True:
        request = self.client_socket.recv(1024).decode('utf-8')
        print('Request: {}'.format(request))

        # parse the request
        request_body = request.split('\r\n\r\n', 1)[1]
        request = request.split('\r\n')
        request_line = request[0].split(' ')
        method = request_line[0]
        path = request_line[1]
        param = ''
        if '?' in path:
            path, param = path.split('?', 1)
        http_version = request_line[2]

        headers = {}
        for line in request[1:-2]:
            key, value = line.split(': ')
            headers[key] = value

        if 'Authorization' not in headers:
            header = 'WWW-Authenticate: Basic realm=Basic realm="Authorization Required"\r\n'
            self.handle_error(401, 'Unauthorized', headers=header)
            return
        Authertication = headers['Authorization']
        base64 = Authertication.split(' ')[-1]
        if base64 not in [client.base64 for client in clients]:
            # self.send_response(401)
            self.handle_error(401, 'Unauthorized')
            return

        # handle the request
        if method == 'GET':
            self.handle_get(path, param)
        elif method == 'POST':
            self.handle_post(path, request[-1])
        elif method == 'HEAD':
            self.handle_head(path, param)
        else:
            self.handle_error(405, 'Method Not Allowed')
        # if 'Connection' in headers:
        #     if headers['Connection'] == 'close':
        #         self.client_socket.close()
        #         break

    def handle_get(self, path, param):
        print(path)
        # if it is url format
        http_url_pattern = re.compile(r'^(/[^/]*)*(\?.*)?$')
        if not bool(re.match(http_url_pattern, path)):
            self.handle_error(400, 'Bad Request')
            return

        # modify to actual path
        if path == '/':
            origin_path = 'data'
        else:
            origin_path = os.path.join("data", path[1:])

        # if the path is a directory, return the index.html file
        if os.path.isdir(origin_path):
            if param == 'SUSTech-HTTP=0' or param == '':
                self.handle_dir(origin_path, path, True)
            elif param == 'SUSTech-HTTP=1':
                self.handle_dir(origin_path, path, False)
            else:
                self.handle_error(400, 'Bad Request')
        # if the path is a file, return the file
        elif os.path.isfile(origin_path):
            self.handle_file(origin_path)
        else:
            self.handle_error(404, 'Not Found')

    def handle_post(self, path, data):
        return

    def handle_head(self, path, param):
        print(path)
        # if it is url format
        http_url_pattern = re.compile(r'^(/[^/]*)*(\?.*)?$')
        if not bool(re.match(http_url_pattern, path)):
            self.handle_error(400, 'Bad Request')
            return
        # modify to actual path
        if path == '/':
            origin_path = 'data'
        else:
            origin_path = os.path.join("data", path[1:])

        # if the path is a directory, return the index.html file
        if os.path.isdir(origin_path):
            if param == '':
                self.handle_dir(origin_path, path, True)
            else:
                self.handle_error(405, 'Method Not Allowed')
        # if the path is a file, return the file
        elif os.path.isfile(origin_path):
            self.handle_file(path, is_head=True)
        else:
            self.handle_error(404, 'Not Found')

    def handle_dir(self, origin_path, web_path, is_html, is_head=False):
        response_body = []
        response_header = ''
        dir_time = datetime.datetime.fromtimestamp(os.path.getmtime(origin_path)).strftime('%a, %d %b %Y %H:%M:%S GMT')
        if is_html:
            response_body = list_directory_html(origin_path, web_path)
            dir_size = len(response_body)
            dir_type = 'text/html'
            response_header = '{} 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\n\r\n'.format(
                'HTTP/1.1', dir_size, dir_type, dir_time)
        else:
            with os.scandir(origin_path) as entries:
                for entry in entries:
                    if entry.is_dir():
                        response_body.append(f'{entry.name}/')
                    else:
                        response_body.append(f'{entry.name}')
            response_body = str(response_body)
            dir_size = len(response_body)
            dir_type = 'text/plain'
            response_header = '{} 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\n\r\n'.format(
                'HTTP/1.1', dir_size, dir_type, dir_time)
        self.client_socket.sendall(response_header.encode("utf-8"))
        if not is_head:
            self.client_socket.sendall(response_body.encode('utf-8'))

    def handle_file(self, path, is_head=False):
        extension = pathlib.Path(path).suffix  # 拓展名
        file_size = os.path.getsize(path)
        file_type = mimetypes.types_map[extension]
        file_time = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%a, %d %b %Y %H:%M:%S GMT')
        response_header = '{} 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\n\r\n'.format(
            'HTTP/1.1', file_size, file_type, file_time)
        self.client_socket.sendall(response_header.encode('utf-8'))

        # send the file
        if not is_head:
            with open(path, 'rb') as f:
                while True:
                    data = f.read(1024)
                    if not data:
                        break
                    self.client_socket.sendall(data)

    def handle_error(self, code, message, headers=None):
        error_message = f"<html><body><h1>{code} {message}</h1></body></html>"
        content_length = len(error_message)
        content_type = "text/html"
        current_time = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        response_header = f'HTTP/1.1 {code} {message}\r\n'
        response_header += f'Content-Length: {content_length}\r\n'
        response_header += f'Content-Type: {content_type}\r\n'
        response_header += f'Last-Modified: {current_time}\r\n'
        if headers:
            response_header += headers + '\r\n'
        response_header += '\r\n'

        print("\r\nResponse Header: {}\r\n".format(response_header))

        self.client_socket.sendall(response_header.encode('utf-8'))
        self.client_socket.sendall(error_message.encode('utf-8'))


def list_directory_html(origin_path, web_path):
    html_content = f"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
    <html>
    <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>Directory listing for ./{origin_path}</title>
    </head>
    <body>
    <h1>Directory listing for ./{origin_path}</h1>
    <hr>
    <ul>
    """
    try:
        links = []
        parent_path = os.path.dirname(web_path)
        print(origin_path)
        print(parent_path)
        with os.scandir(origin_path) as entries:
            if origin_path != 'data':
                links.extend([f'<a href="/">/</a>', f'<a href="{parent_path}">../</a>'])
                for entry in entries:
                    if entry.is_dir():
                        links.append(f'<li><a href="{web_path[1:]}/{entry.name}">{entry.name}/</a></li>')
                    else:
                        links.append(f'<li><a href="{web_path[1:]}/{entry.name}">{entry.name}</a></li>')
            else:
                for entry in entries:
                    if entry.is_dir():
                        links.append(f'<li><a href="{web_path[1:]}{entry.name}">{entry.name}/</a></li>')
                    else:
                        links.append(f'<li><a href="{web_path[1:]}{entry.name}">{entry.name}</a></li>')
        print(links)
        html_content += '\r\n'.join(links)
        # 合并所有链接
        html_content1 = """
        </ul>
        <hr>
        </body>
        </html>
        """
        html_content += html_content1
        return html_content
    except FileNotFoundError:
        return "Directory not found"
    except Exception as e:
        return f"Error: {str(e)}"


terminate_flag = False


def signal_handler(sig, frame):
    global terminate_flag
    print('Ctrl+C pressed. Exiting gracefully...')
    terminate_flag = True


signal.signal(signal.SIGINT, signal_handler)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 8080))  # bind the socket to host and port

while not terminate_flag:
    server_socket.listen(5)  # start listening for incoming connections, 5 is the max number of queued connections
    client_socket, addr = server_socket.accept()  # accept the connection, addr is the address bound to the socket on the other end of the connection, including the port number and IP address
    print('Got a connection from {}'.format(addr))

    # create a new thread to handle the request
    thread = HttpServer(client_socket, addr)
    thread.start()
    print('Thread started')

server_socket.close()
print('Server closed')
