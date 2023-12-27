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
import uuid

from Logger import Logger

# other module can be used according to https://github.com/Leosang-lx/SUSTech-CS305-2023Fall
import re


class ClientAccount:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.base64 = self.getBase64()

    def getBase64(self):
        return base64.b64encode('{}:{}'.format(self.username, self.password).encode('utf-8')).decode('utf-8')
    
class Session:
    def __init__(self, session_id, athorization, username, time, timeout):
        self.session_id = session_id
        self.athorization = athorization
        self.username = username
        self.time = time
        self.timeout = timeout


clients = [ClientAccount('client1', '123'),
           ClientAccount('client2', '123'),
           ClientAccount('client3', '123')]

sessions = []


class HttpServer(threading.Thread):
    def __init__(self, client_socket, addr):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.addr = addr
        self.name = threading.current_thread().name
        self.session = None
        self.clientUsername = None
        self.response_header = ""
        self.chunk_size = 128

    def run(self):
        try:
            self.handle_request()
        except Exception as e:
            self.client_socket.close()
            raise e

    def handle_request(self):
        while True:
            request = self.client_socket.recv(4096).decode('utf-8')
            if request == '':
                break
            Logger.debug('{} Request from {}:'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), self.addr))
            Logger.text(request)

            # parse the request
            request_header, request_body = request.split('\r\n\r\n', 1)
            request_header = request_header.split('\r\n')
            request_line = request_header[0].split(' ')
            method = request_line[0]
            path = request_line[1]
            params = {}

            if '?' in path:
                path, query_string = path.split('?', 1)
                # 解析查询字符串为字典
                params = {k: v for k, v in [param.split('=') for param in query_string.split('&')]}
            http_version = request_line[2]


            headers = {}
            for line in request_header[1:]:
                key, value = line.split(': ')
                headers[key] = value

            header = 'WWW-Authenticate: Basic realm=Basic realm="Authorization Required"\r\n'            
            if 'Cookie' in headers:
                cookie = headers['Cookie'].split('=')[1]
                for session in sessions:
                    if session.time + session.timeout < time.time():
                        sessions.remove(session)
                        continue
                    if session.session_id == cookie:
                        self.session = session
                        break
                if self.session is None:
                    self.handle_error(401, 'Unauthorized', headers=header, log='session not found or timeout')
                    return
                else:
                    Logger.debug('session: {} refreshed.'.format(self.session.session_id))
                    self.session.time = time.time()
            elif 'Authorization' in headers:
                Authertication = headers['Authorization']
                base64 = Authertication.split(' ')[-1]
                
                for client in clients:
                    if client.base64 == base64:
                        self.clientUsername = client.username
                        break
                if self.clientUsername is None:
                    self.handle_error(401, 'Unauthorized', headers=header)
                    return
                
                session_id = self.generate_session(Authertication, self.clientUsername)
                self.response_header += 'Set-Cookie: session-id={}\r\n'.format(session_id)
            else:
                self.handle_error(401, 'Unauthorized', headers=header)
                return

            
            if 'Content-Type' in headers:
                content_type = headers['Content-Type']
            else:
                content_type = None

            # handle the request
            if method == 'GET':
                # for Breakpoint Transmission
                if 'Range' in headers:
                    self.handle_get(path, params, is_range=True)
                else:
                    self.handle_get(path, params)
            elif method == 'POST':
                # for Breakpoint Transmission
                if 'Range' in headers:
                    self.handle_post(request_body, params, methed=path, content_type=content_type, is_range=True)
                else:
                    self.handle_post(request_body, params, methed=path, content_type=content_type)
            elif method == 'HEAD':
                self.handle_head(path, params)
            else:
                self.handle_error(405, 'Method Not Allowed')
            if 'Connection' in headers:
                if headers['Connection'] == 'close':
                    break

        Logger.info('{}Connection closed {}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), self.addr))
        self.client_socket.close()

    def handle_get(self, path, param, is_range=False):
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
            if 'SUSTech-HTTP' not in param or param['SUSTech-HTTP'] == '0':
                if 'chunked' not in param or param['chunked'] == '0':
                    self.handle_dir(origin_path, path, is_html=True)
                else:
                    self.handle_dir(origin_path, path, is_html=True, is_chunked=True)
            elif param['SUSTech-HTTP'] == '1':
                if 'chunked' not in param or param['chunked'] == '0':
                    self.handle_dir(origin_path, path)
                else:
                    self.handle_dir(origin_path, path, is_chunked=True)
            else:
                self.handle_error(400, 'Bad Request')
        # if the path is a file, return the file
        elif os.path.isfile(origin_path):
            if 'chunked' not in param or param['chunked'] == '0':
                self.handle_file(origin_path)
            else:
                self.handle_file(origin_path, is_chunked=True)
        else:
            self.handle_error(404, 'Not Found')

    def handle_post(self, data, param,  methed, content_type=None,is_range=False):
        http_url_pattern = re.compile(r'^(/[^/]*)*(\?.*)?$')
        if not bool(re.match(http_url_pattern, methed)) or 'path' not in param:
            self.handle_error(400, 'Bad Request')
            return
        
        path = param['path']

        if path.startswith('/'):
            path = path[1:]

        if not path.endswith('/'):
            path += '/'
        
        username = path.split('/')[0]
        # Logger.debug('username: {}, self.clientUsername: {}, path: {}'.format(username, self.clientUsername, path))
        if username != self.clientUsername:
            self.handle_error(403, 'Forbidden')
            return
        
        target_path = os.path.normpath(os.path.join('data', path))
        Logger.debug('target_path: {}'.format(target_path))
        if not os.path.exists(target_path):
            self.handle_error(404, 'Not Found')
            return
        
        Logger.debug('data: {}'.format(data))
        
        operation = methed.split('/')[-1]
        if operation == 'upload':
            if not os.path.isdir(target_path):
                self.handle_error(400, 'Bad Request')
                return
            else:
                try:
                    boundary = content_type.split('boundary=')[1]
                except:
                    self.handle_error(400, 'Bad Request')
                    return
                files = data.split('--' + boundary)[1:-1]
                for file in files:
                    file = file.split('\r\n\r\n')
                    file_name = file[0].split('; ')[2].split('=')[1][1:-1]
                    file_data = file[1][:-2]
                    with open(os.path.join(target_path, file_name), 'wb') as f:
                        f.write(file_data.encode('utf-8'))
                self.handle_response(200, 'OK')
        elif operation == 'delete':
            if os.path.isdir(target_path):
                try:
                    os.rmdir(target_path)
                    self.handle_response(200, 'OK')
                except:
                    self.handle_error(400, 'Bad Request: directory is not empty')
            else:
                os.remove(target_path)
                self.handle_response(200, 'OK')
        else:
            self.handle_error(405, 'Method Not Allowed')

    def handle_head(self, path, param):
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
            if param == {}:
                self.handle_dir(origin_path, path, is_html=True, is_head=True)
            else:
                self.handle_error(405, 'Method Not Allowed')
        # if the path is a file, return the file
        elif os.path.isfile(origin_path):
            self.handle_file(path, is_head=True)
        else:
            self.handle_error(404, 'Not Found')

    def chunks(data, chunk_size=1024):
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]

    def handle_dir(self, origin_path, web_path, is_html=False, is_head=False, is_chunked=False):
        response_body = []
        dir_type = ''
        dir_time = datetime.datetime.fromtimestamp(os.path.getmtime(origin_path)).strftime('%a, %d %b %Y %H:%M:%S GMT')

        # for HTML
        if is_html:
            response_body = list_directory_html(origin_path, web_path)
            dir_type = 'text/html'
        else:
            with os.scandir(origin_path) as entries:
                for entry in entries:
                    if entry.is_dir():
                        response_body.append(f'{entry.name}/')
                    else:
                        response_body.append(f'{entry.name}')
            response_body = str(response_body)
            dir_type = 'text/plain'

        # for Chunk
        if is_chunked:
            response_header = '{} 200 OK\r\nContent-Type: {}\r\nLast-Modified: {}\r\nTransfer-Encoding: chunked\r\n'.format(
                'HTTP/1.1', dir_type, dir_time)
        else:
            dir_size = len(response_body)
            response_header = '{} 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\n'.format(
                'HTTP/1.1', dir_size, dir_type, dir_time)
        
        # for session
        response_header += self.response_header if self.response_header else ''
        response_header += '\r\n'
        self.response_header = None
        
        # send header
        self.client_socket.sendall(response_header.encode("utf-8"))
        Logger.debug("{} Response to {}:".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), self.addr))
        Logger.text(response_header)

        if not is_head:
            if is_chunked:
                Logger.debug('Chunked Transfer:')
                for chunk in self.chunks(response_body, self.chunk_size):
                    chunk_size = hex(len(chunk))[2:]
                    self.client_socket.sendall((chunk_size + '\r\n').encode('utf-8'))
                    self.client_socket.sendall(chunk.encode('utf-8'))
                    self.client_socket.sendall('\r\n'.encode('utf-8'))
                    Logger.text(chunk)
                self.client_socket.sendall('0\r\n\r\n'.encode('utf-8'))
                Logger.text('0\r\n\r\n')
            else:
                self.client_socket.sendall(response_body.encode('utf-8'))
                Logger.text(response_body)

    def handle_file(self, path, is_head=False, is_chunked=False):
        extension = pathlib.Path(path).suffix
        file_type = mimetypes.types_map[extension]
        file_time = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%a, %d %b %Y %H:%M:%S GMT')

        # for Chunk
        if is_chunked:
            response_header = '{} 200 OK\r\nContent-Type: {}\r\nLast-Modified: {}\r\nTransfer-Encoding: chunked\r\n'.format(
                'HTTP/1.1', file_type, file_time)
        else:
            file_size = os.path.getsize(path)
            response_header = '{} 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\n'.format(
                'HTTP/1.1', file_size, file_type, file_time)
            
        # for session
        response_header += self.response_header if self.response_header else ''
        response_header += '\r\n'
        self.response_header = None

        # send header
        self.client_socket.sendall(response_header.encode('utf-8'))
        Logger.debug("{} Response to {}:".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), self.addr))
        Logger.text(response_header)

        # send the file
        if not is_head:
            if is_chunked:
                with open(path, 'rb') as f:
                    while True:
                        data = f.read(self.chunk_size)
                        if not data:
                            break
                        chunk_size = hex(len(data))[2:]
                        self.client_socket.sendall((chunk_size + '\r\n').encode('utf-8'))
                        self.client_socket.sendall(data)
                        self.client_socket.sendall('\r\n'.encode('utf-8'))
                        Logger.text(data)
                self.client_socket.sendall('0\r\n\r\n'.encode('utf-8'))
                Logger.text('0\r\n\r\n')
            else:
                with open(path, 'rb') as f:
                    while True:
                        data = f.read(1024)
                        if not data:
                            break
                        self.client_socket.sendall(data)
                        Logger.text(data)

    def handle_error(self, code, message, headers=None, log=None):
        self.handle_response(code, message, headers, is_error=True, log=log)

    def handle_response(self, code, message, headers=None, data=None,  is_error=False, log=None):
        response_header = f'HTTP/1.1 {code} {message}\r\n'
        response_body = f'<html><body><h1>{code} {message}</h1></body></html>'
        content_length = len(response_body)
        content_type = "text/html"
        current_time = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        response_header += f'Content-Length: {content_length}\r\n'
        response_header += f'Content-Type: {content_type}\r\n'
        response_header += f'Last-Modified: {current_time}\r\n'

        if headers:
            response_header += headers + '\r\n'
        response_header += '\r\n'

        if is_error:

            Logger.warn("{} Response to {}, due to ({} {}, log: {}):".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), self.addr, code, message, log))
            Logger.text(response_header + response_body)
        else:
            Logger.debug("{} Response to {}:".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), self.addr))
            Logger.text(response_header + response_body)

        self.client_socket.sendall(response_header.encode('utf-8'))
        self.client_socket.sendall(response_body.encode('utf-8'))

    # for cookie
    def generate_session(self, auth, username):
        session_id = str(uuid.uuid4())
        session = Session(session_id, auth, username, time.time(), 3600)
        sessions.append(session)
        return session_id


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
        Logger.debug("Web_path: \'{}\'".format(parent_path, web_path))
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
        # print(links)
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
    

def main():
    parser = argparse.ArgumentParser(description='A simple HTTP server.')
    parser.add_argument('-p', '--port', type=int, default=8080, help='TCP port to listen on (default: 8080)')
    parser.add_argument('-i', '--ip', default='localhost', help='IP address to listen on (default: localhost)')
    args = parser.parse_args()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((args.ip, args.port))  # bind the socket to host and port

    Logger.info('{} Server started at {}:{}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), args.ip, args.port))

    while True:
        try:
            server_socket.listen(5)
            client_socket, addr = server_socket.accept()  # accept the connection, addr is the address bound to the socket on the other end of the connection, including the port number and IP address
            # create a new thread to handle the request
            thread = HttpServer(client_socket, addr)
            Logger.info('{} {} get a connection from {}.'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), thread.name, addr))
            thread.start()

        except Exception as e:
            Logger.error('Exception: {}'.format(e))
            traceback.print_exc()

        # finally:
        #     server_socket.close()
        #     print('Server closed')


if __name__ == '__main__':
    main()
