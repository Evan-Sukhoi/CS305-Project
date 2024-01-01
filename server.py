"""
can only use the python libraries including {argparse socket
mimetypes io sys time datetime os signal threading pathlib traceback json}
"""

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
import gzip
import Encryption as e
import urllib.parse

mimetypes.init()
mimetypes.add_type('application/vnd.openxmlformats-officedocument.presentationml.presentation', '.pptx')
mimetypes.add_type('text/markdown', '.md')
mimetypes.add_type('application/x-7z-compressed', '.7z')
mimetypes.add_type('Unknown', '.rpf')


class ClientAccount:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.base_64 = self.getBase64()

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
        self.response_header += 'Access-Control-Allow-Headers: Authorization\r\n'
        self.response_header += 'Access-Control-Allow-Methods: GET, POST, HEAD\r\n'
        self.response_header += 'Access-Control-Allow-Origin: *\r\n'
        self.chunk_size = 128
        self.private_key, self.public_key = e.generate_keys()
        self.sym_key = None

    def run(self):
        try:
            self.handle_request()
        except Exception as e:
            Logger.error('Exception: {} at line {}'.format(e, e.__traceback__.tb_next.tb_lineno))
            self.handle_error(400, 'Bad Request')
            self.client_socket.close()
            raise e

    def handle_request(self):
        while True:
            request_header = b''
            request_body = b''
            request = self.client_socket.recv(4096)
            while request.find(b'\r\n\r\n') == -1: # if the request hearder is not complete
                request += self.client_socket.recv(4096)
            if request == b'':
                break
            try:
                request_header, request_body = request.split(b'\r\n\r\n', 1)
            except:
                request_header = request
                Logger.warn(request)
            request_header = request_header.decode('utf-8')
            Logger.debug(
                '{} Request headers from {}:'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), self.addr))
            Logger.text(request_header)

            # parse the request
            # request_header, request_body = request.split('\r\n\r\n', 1)
            request_header = request_header.split('\r\n')
            method, path, http_version = request_header[0].split(' ')
            path = urllib.parse.unquote(path)
            params = {}

            if '?' in path:
                path, query_string = path.split('?', 1)
                # 解析查询字符串为字典
                params = {k: v for k, v in [param.split('=') for param in query_string.split('&')]}

            headers = {}
            for line in request_header[1:]:
                key, value = line.split(': ')
                headers[key] = value

            if 'Content-Length' in headers:
                request_content_length = headers['Content-Length']
                while len(request_body) < int(request_content_length):
                    Logger.debug('Supplement from {}'.format(self.addr))
                    request = self.client_socket.recv(4096)
                    request_body += request
                    # Logger.text(request)

            # handle the encryption
            if 'Encryption' in headers and headers['Encryption'] == 'enable':
                if 'Authorization' in headers:
                    headers['Authorization'] = e.symmetric_decrypt(self.sym_key,
                                                                   base64.b64decode(headers['Authorization'])).decode(
                        'utf-8')
                request_body = e.symmetric_decrypt(self.sym_key, base64.b64decode(request_body)).decode('utf-8')

            # handle the authentication
            if method == 'OPTIONS':
                self.handle_response(200, 'OK', headers=self.response_header)
                return
            header = 'WWW-Authenticate: Basic realm=Basic realm="Authorization Required"\r\n'
            cookie = None
            if 'Authorization' in headers:
                Authertication = headers['Authorization']
                base_64 = Authertication.split(' ')[-1]

                for client in clients:
                    if client.base_64 == base_64:
                        self.clientUsername = client.username
                        break
                if self.clientUsername is None:
                    self.handle_error(401, 'Unauthorized', headers=header)
                    return
                if 'Cookie' in headers:
                    cookie = headers['Cookie'].split('=')[1]
            elif 'Cookie' in headers:
                cookie = headers['Cookie'].split('=')[1]
                for session in sessions:
                    if session.time + session.timeout < time.time():
                        sessions.remove(session)
                        continue
                    if session.session_id == cookie:
                        self.session = session
                        cookie = session.session_id
                        break
                if self.session is None:
                    self.handle_error(401, 'Unauthorized', headers=header, log='session not found or timeout')
                    return
                else:
                    Logger.debug('session: {} refreshed.'.format(self.session.session_id))
                    self.session.time = time.time()
            else:
                self.handle_error(401, 'Unauthorized', headers=header)
                return

            if cookie is None:
                session_id = self.generate_session(Authertication, self.clientUsername)
                self.response_header += 'Set-Cookie: session-id={}\r\n'.format(session_id)

            if 'Content-Type' in headers:
                content_type = headers['Content-Type']
            else:
                content_type = None

            # write message
            if 'Encryption' in headers and headers['Encryption'] == 'enable':
                with open('data/test_encryption.txt', 'w') as file:
                    file.write(request_body)
                self.handle_response(200, 'OK')
                return

            # handle the request
            if method == 'GET':
                if 'Range' in headers:  # for Breakpoint Transmission
                    range = headers['Range']
                    if re.match(r'^bytes=', range):  # eg. bytes=0-100
                        range = range.split('=')[1]
                    self.handle_get(path, params, range=range)
                else:
                    self.handle_get(path, params)
            elif method == 'POST':
                self.handle_post(request_body, params, method=path, content_type=content_type)
            elif method == 'HEAD':
                if 'Range' in headers:  # for Breakpoint Transmission
                    range = headers['Range']
                    if re.match(r'^bytes=', range):  # eg. bytes=0-100
                        range = range.split('=')[1]

                    if re.match(r'^\d+-\d+$|^\d+-$|^-\d+$', range):  # eg. 0-100, 100-, -100
                        self.handle_get(path, params, range=range, is_head=True)
                    else:
                        self.handle_error(400, 'Bad Request')
                        return
                else:
                    self.handle_get(path, params, is_head=True)
            else:
                self.handle_error(405, 'Method Not Allowed')
            if 'Connection' in headers:
                if headers['Connection'] == 'close':
                    break

        Logger.info('{} Connection closed {}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), self.addr))
        self.client_socket.close()

    def handle_get(self, path, param, range=None, is_head=False):
        # if it is url format
        http_url_pattern = re.compile(r'^(/[^/]*)*(\?.*)?$')
        if not bool(re.match(http_url_pattern, path)):
            self.handle_error(400, 'Bad Request')
            return

        if 'Encryption' in param and param["Encryption"] == '1':
            self.handle_encryption()
            return

        # modify to actual path
        origin_path = os.path.join("data", path[1:])

        # if the path is a directory, return the index.html file
        if os.path.isdir(origin_path):
            if 'SUSTech-HTTP' not in param or param['SUSTech-HTTP'] == '0':
                if 'chunked' not in param or param['chunked'] == '0':
                    self.handle_dir(origin_path, path, is_html=True, range=range, is_head=is_head)
                else:
                    self.handle_dir(origin_path, path, is_html=True, is_chunked=True, range=range, is_head=is_head)
            elif param['SUSTech-HTTP'] == '1':
                if 'chunked' not in param or param['chunked'] == '0':
                    self.handle_dir(origin_path, path, range=range, is_head=is_head)
                else:
                    self.handle_dir(origin_path, path, is_chunked=True, range=range, is_head=is_head)
            else:
                self.handle_error(400, 'Bad Request')
        # if the path is a file, return the file
        elif os.path.isfile(origin_path):
            # self.response_header += 'Content-Disposition: attachment; filename="{}"\r\n'.format(os.path.basename(origin_path))
            Logger.debug('path: {}'.format(origin_path))
            if 'chunked' not in param or param['chunked'] == '0':
                self.handle_file(origin_path, range=range, is_head=is_head)
            else:
                self.handle_file(origin_path, is_chunked=True, range=range, is_head=is_head)
        else:
            Logger.debug('path not found: {}'.format(origin_path))
            self.handle_error(404, 'Not Found')

    def handle_post(self, data, param, method, content_type=None):
        # for asy_encryption
        if method == '/sendkey':
            self.sym_key = e.decrypt_with_private_key(self.private_key, base64.b64decode(data))
            self.handle_response(200, 'OK')
            return

        http_url_pattern = re.compile(r'^(/[^/]*)*(\?.*)?$')
        if not bool(re.match(http_url_pattern, method)):
            self.handle_error(400, 'Bad Request')
            return

        operation = method.split('/')[-1]

        if operation != 'upload' and operation != 'delete' and operation != 'mkdir':
            self.handle_error(405, 'Method Not Allowed')
            return

        if 'path' not in param:
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
        if not os.path.exists(target_path) and operation != 'mkdir':
            self.handle_error(404, 'Not Found')
            return

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
                boundary = ('--' + boundary).encode('utf-8')
                files = data.split(boundary)[1:-1]
                content = b''
                for file in files:
                    file = file.split(b'\r\n\r\n', 1)
                    name_index = file[0].find(b'filename="') + 10
                    file_name = file[0][name_index:file[0].find(b'"', name_index)].decode('utf-8')
                    file_data = file[1][:-2]
                    # Logger.debug('target_path: {}, file_name: {}, file_data: {}'.format(target_path, file_name, file_data))
                    content += file_data
                with open(os.path.join(target_path, file_name), 'wb') as f:
                    f.write(content)
                self.handle_response(200, 'OK')
        elif operation == 'delete':
            if os.path.isdir(target_path):
                try:
                    os.rmdir(target_path)
                    self.handle_response(200, 'OK')
                except:
                    self.handle_error(409, 'Conflict', log='directory not empty')
            else:
                os.remove(target_path)
                self.handle_response(200, 'OK')
        elif operation == 'mkdir':
            Logger.debug('target_path: {}'.format(target_path))
            if os.path.isdir(target_path):
                self.handle_error(409, 'Conflict', log='directory already exists')
            else:
                os.mkdir(target_path)
                self.handle_response(200, 'OK')

    def chunks(self, data, chunk_size=1024):
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]

    def handle_range(self, length, range):
        ranges = range.split(',')
        range_pairs = []
        for r in ranges:
            if re.match(r'^\d+-\d+$', r):  # eg. 0-100
                start, end = r.split('-')
                if int(start) > int(end) or int(start) < 0 or int(end) >= length:
                    self.handle_error(416, 'Range Not Satisfiable')
                    return
                range_pairs.append((int(start), int(end)))
            elif re.match(r'^\d+-$', r):  # eg. 100-
                start = int(r.split('-')[0])
                if start < 0:
                    self.handle_error(416, 'Range Not Satisfiable')
                    return
                range_pairs.append((start, length - 1))
            elif re.match(r'^-\d+$', r):  # eg. -100
                end = int(r.split('-')[1])
                if end >= length:
                    self.handle_error(416, 'Range Not Satisfiable')
                    return
                range_pairs.append((length - end, length - 1))
            else:
                self.handle_error(416, 'Range Not Satisfiable')
                return
        # sort the range pairs according to the start
        range_pairs.sort(key=lambda x: x[0])
        last_rp = range_pairs[0]
        last_rp_index = 0
        rm_num = []
        for rp in range_pairs[1:]:
            if last_rp[1] >= rp[0] - 1:
                Logger.debug('last_rp: {}, rp: {}'.format(last_rp, rp))
                last_rp = (last_rp[0], max(rp[1], last_rp[1]))
                range_pairs[last_rp_index] = last_rp
                rm_num.append(range_pairs.index(rp))
            else:
                Logger.debug('last_rp: {}, rp: {}'.format(last_rp, rp))
                last_rp = rp
        Logger.debug('range_pairs: {}'.format(range_pairs))
        for i in rm_num[::-1]:
            range_pairs.pop(i)
        Logger.debug('range_pairs: {}'.format(range_pairs))
        return range_pairs

    def generate_boundary(self):
        unique_id = uuid.uuid4().hex[:13]  # eg. 1a2b3c4d5e6f7
        return unique_id

    def handle_send(self, response_body, content_type, last_modified, is_chunked=False, range_info=None, is_head=False):
        code = '200 OK'
        content_length_unconpressed = len(response_body)
        response_body = [response_body]
        self.response_header += 'Access-Control-Allow-Headers: Range\r\n'
        if range_info is not None:
            self.response_header += 'Accept-Ranges: bytes\r\n'
            boundary = self.generate_boundary()
            origin_content_type = content_type.encode('utf-8')
            content_type = 'multipart/byteranges; boundary={}'.format(boundary)
            boundary = boundary.encode('utf-8')
            code = '206 Partial Content'
            range_pairs = self.handle_range(content_length_unconpressed, range_info)
            if len(range_pairs) == 1:
                rp = range_pairs[0]
                response_body = response_body[0][rp[0]:rp[1] + 1]
                response_body = [response_body]
                self.response_header += 'Content-Range: bytes ' + str(rp[0]) + '-' + \
                                            str(rp[1]) + '/' + str(content_length_unconpressed) + '\r\n';
            else:
                response_body_range = []
                if range_pairs is None:
                    return
                for rp in range_pairs:
                    response_range = b'--' + boundary + b'\r\n' + \
                                    b'Content-Type: ' + origin_content_type + b'\r\n' + \
                                    b'Content-Range: bytes ' + str(rp[0]).encode('utf-8') + b'-' + \
                                    str(rp[1]).encode('utf-8') + b'/' + \
                                    str(content_length_unconpressed).encode('utf-8') + b'\r\n\r\n' + \
                                    response_body[0][rp[0]:rp[1] + 1] + b'\r\n'
                    response_body_range.append(response_range)
                tail = b'--' + boundary + b'--\r\n'
                response_body_range[-1] += tail
                response_body = response_body_range

        using_gzip = True
        content_length = 0
        Logger.debug('content_length_unconpressed: {}'.format(content_length_unconpressed))
        for i in range(len(response_body)):
            if using_gzip:
                response_body[i] = gzip.compress(response_body[i])
            # response_body[i] = binascii.hexlify(response_body[i])
            content_length += len(response_body[i])
        Logger.debug('content_length_conpressed: {}'.format(content_length))

        # for chunk
        if is_chunked:
            response_header = '{} {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\nTransfer-Encoding: chunked\r\n'.format(
                'HTTP/1.1', code, content_type, last_modified)
        else:
            response_header = '{} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\n'.format(
                'HTTP/1.1', code, content_length, content_type, last_modified)
            
        if using_gzip:
            response_header += 'Content-Encoding: gzip\r\n'

        # for session
        response_header += self.response_header if self.response_header else ''
        response_header += '\r\n'
        self.response_header = ''

        # send header
        self.client_socket.sendall(response_header.encode('utf-8'))
        Logger.debug("Response to {}:".format(self.addr))
        Logger.text(response_header)

        # send content
        if not is_head:
            for rb in response_body:
                if is_chunked:
                    Logger.debug('Chunked Transfer:')
                    for chunk in self.chunks(rb, self.chunk_size):
                        chunk_size = hex(len(chunk))[2:]
                        self.client_socket.sendall((chunk_size + '\r\n').encode('utf-8'))
                        self.client_socket.sendall(chunk)
                        self.client_socket.sendall('\r\n'.encode('utf-8'))
                        Logger.text(chunk)
                    self.client_socket.sendall('0\r\n\r\n'.encode('utf-8'))
                    Logger.text('0\r\n\r\n')
                else:
                    self.client_socket.sendall(rb)
                    # Logger.text(response_body)
                Logger.debug('range no. {} sent'.format(response_body.index(rb)))
                # Logger.text(rb)

    def handle_dir(self, origin_path, web_path, is_html=False, is_head=False, is_chunked=False, range=None):
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
            dir_type = 'text/plain'
        response_body = str(response_body).encode('utf-8')
        self.handle_send(response_body, dir_type, dir_time, is_chunked=is_chunked, range_info=range, is_head=is_head)

    def handle_file(self, path, is_head=False, is_chunked=False, range=None):
        extension = pathlib.Path(path).suffix
        file_type = mimetypes.types_map[extension]
        file_time = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%a, %d %b %Y %H:%M:%S GMT')
        with open(path, 'rb') as f:
            response_body = f.read()
        self.handle_send(response_body, file_type, file_time, is_chunked=is_chunked, range_info=range, is_head=is_head)

    def handle_error(self, code, message, headers=None, log=None):
        self.handle_response(code, message, headers, is_error=True, log=log)

    def handle_response(self, code, message, headers=None, data=None, is_error=False, log=None):
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
            Logger.warn("Response to {}, due to ({} {}, log: {}):".format(self.addr, code, message, log))
            Logger.text(response_header + response_body)
        else:
            Logger.debug("Response to {}:".format(self.addr))
            Logger.text(response_header + response_body)

        self.client_socket.sendall(response_header.encode('utf-8'))
        self.client_socket.sendall(response_body.encode('utf-8'))

    # for cookie
    def generate_session(self, auth, username):
        session_id = str(uuid.uuid4())
        session = Session(session_id, auth, username, time.time(), 3600)
        sessions.append(session)
        return session_id

    def handle_encryption(self):
        response_body = self.public_key
        response_header = '{} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\n\r\n'.format(
            'HTTP/1.1', '200 OK', len(response_body), 'text/plain',
            datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'))
        self.client_socket.sendall(response_header.encode('utf-8') + response_body)

def get_icon_type(entry):
    icon_path = '/resource/icons/default.png'
    file_type = 'Unknown'
    if entry.is_dir():
        icon_path = '/resource/icons/file-folder.png'
        file_type = 'Folder'
    else:
        file_extension = os.path.splitext(entry.name)[1].lower()
        file_type = file_extension[1:].upper()
        if file_extension == '.png' or file_extension == '.jpg' or file_extension == '.jpeg' or file_extension == '.gif' or file_extension == '.bmp':
            icon_path = '/resource/icons/image.png'
        elif file_extension == '.js':
            icon_path = '/resource/icons/js-file.png'
        elif file_extension == '.mp3' or file_extension == '.wav' or file_extension == '.flac':
            icon_path = '/resource/icons/music.png'
        elif file_extension == '.pdf':
            icon_path = '/resource/icons/pdf.png'
        elif file_extension == '.php':
            icon_path = '/resource/icons/php.png'
        elif file_extension == '.ppt' or file_extension == '.pptx':
            icon_path = '/resource/icons/ppt.png'
            file_type = 'PowerPoint'
        elif file_extension == '.txt':
            icon_path = '/resource/icons/txt.png'
            file_type = 'Text'
        elif file_extension == '.md':
            icon_path = '/resource/icons/md.png'
            file_type = 'Markdown'
        elif file_extension == '.mp4' or file_extension == '.avi' or file_extension == '.mov':
            icon_path = '/resource/icons/video.png'
        elif file_extension == '.doc' or file_extension == '.docx':
            icon_path = '/resource/icons/word.png'
            file_type = 'Word'
        elif file_extension == '.xls' or file_extension == '.xlsx':
            icon_path = '/resource/icons/xls.png'
            file_type = 'Excel'
        elif file_extension == '.zip' or file_extension == '.rar' or file_extension == '.7z':
            icon_path = '/resource/icons/zip.png'
        elif file_extension == '.py':
            icon_path = '/resource/icons/py.png'
            file_type = 'Python'
        elif file_extension == '.apk':
            icon_path = '/resource/icons/apk.png'
            file_type = 'Android Package'
        elif file_extension == '.html':
            icon_path = '/resource/icons/html.png'
    return icon_path, file_type


def get_folder_size(folder_path):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for f in filenames:
            file_path = os.path.join(dirpath, f)
            total_size += os.path.getsize(file_path)
    return transfer_size(total_size)


def transfer_size(size):
    print("size: {}".format(size))
    if size < 1024:
        return '{} B'.format(size)
    elif size < 1024 * 1024:
        return '{:.2f} KB'.format(size / 1024)
    elif size < 1024 * 1024 * 1024:
        return '{:.2f} MB'.format(size / 1024 / 1024)
    else:
        return '{:.2f} GB'.format(size / 1024 / 1024 / 1024)


def list_directory_html(origin_path, web_path):
    links = []
    # split the path with '/' or '\'
    path_parts = os.path.normpath(origin_path).split(os.sep)
    parent_path = os.path.dirname(web_path)
    print(path_parts)
    folder_links_html = '<div class="folder-links">'
    folder_links_html += '<ul>'
    c_path = '/'
    folder_links_html += f'<li><a href="javascript:void(0)"><img src="/resource/icons/monitor.png" width="20" height="20"></a></li>'
    folder_links_html += f'<li><a href="{c_path}">data</a></li>'
    for i in range(1, len(path_parts)):
        c_path += path_parts[i] + '/'
        folder_links_html += f'<li><a href="{c_path}">{path_parts[i]}</a></li>'
    folder_links_html += '</ul></div>'
    print(folder_links_html)

        # <script src="https://www.unpkg.com/axios@1.3.5/dist/axios.min.js"></script>
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <link rel="stylesheet" href="/resource/styles/fileList.css">
        <script src="/resource/scripts/del.js"></script>
        <script src="/resource/scripts/StreamSaver.js"></script>
        <meta charset="UTF-8">
        <title>🤘LeeTown HTTP Server🤘 {origin_path}</title>
    </head>
    <body>
        <h1>
            <img src="/resource/icons/DingZhen.png" width="60" height="60">
            LeeTown HTTP Server
            <img src="/resource/icons/DingZhen.png" width="60" height="60">
        </h1>
        <div class="toolbar">
            <div class="toolbar-left">
                <a href="/" class="navigation-link"><img src="/resource/icons/home.png" width="30" height="30">/</a>
                <a href="{parent_path}" class="navigation-link"><img src="/resource/icons/go-back.png" width="30" height="30">../</a>
                {folder_links_html}
            </div>
            <div class="toolbar-right">

                <button onclick="uploadFile('{web_path}')"><img src="/resource/icons/upload.png" width="25" height="25">
                    <span class="button-text">Upload</span>
                </button>
                <button onclick="makeDir('{web_path}')"><img src="/resource/icons/add-folder.png" width="25" height="25">
                    <span class="button-text">Add Folder</span>
                </button>
            </div>
        </div>
        <table>
            <tr>
                <th>File Name</th>
                <th>File Type</th>
                <th>Last Modified</th>
                <th>Size</th>
                <th>Operation</th>
            </tr>
    """
    try:
        if web_path == '/':
            web_path = ''
        Logger.debug('origin_path: {}'.format(origin_path))
        Logger.debug('web_path: {}'.format(web_path))
        with os.scandir(origin_path) as entries:
            delete_icon_path = '/resource/icons/delete.png'
            # if origin_path != 'data\\':
            #     links.extend([f'<li><a href="/"><img src="/resource/icons/home.png" width="20" height="20">/   </a>', 
            #                 f'<a href="{parent_path}"><img src="/resource/icons/go-back.png" width="20" height="20">../</a></li>'])
            for entry in entries:
                icon_path, file_type = get_icon_type(entry)
                file_path = os.path.join(origin_path, entry.name)
                if entry.is_dir(): # folder
                    modification_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime(
                        '%Y-%m-%d %H:%M:%S')
                    size = get_folder_size(file_path)
                    links.append(
                        f'<tr><td><a href="{web_path}/{entry.name}"><img src="{icon_path}" width="25" height="25">{entry.name}/</a></td>')
                    links.append(f'<td>{file_type}</td><td>{modification_time}</td><td>{size}</td>')
                    # delete the folder
                    links.append(
                        f'<td><button onclick="deleteFile(\'{web_path}/{entry.name}\')"><img src="{delete_icon_path}" width="25" height="25">\
                                    <span class="button-text">Delete</span>\
                                    </button></td></tr>')
                else: # file
                    modification_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime(
                        '%Y-%m-%d %H:%M:%S')
                    content_length = os.path.getsize(file_path)
                    file_size = transfer_size(content_length)
                    # download link
                    links.append(
                        # f'<tr><td><a href="#" onclick="rangeDownload(\'{web_path}/{entry.name}\', \'{content_length}\',\'{entry.name}\')"><img src="{icon_path}" width="25" height="25">{entry.name}</a></td>')
                        f'<tr><td><a href="{web_path}/{entry.name}"><img src="{icon_path}" width="25" height="25">{entry.name}</a></td>')
                    # other information
                    links.append(f'<td>{file_type}</td><td>{modification_time}</td><td>{file_size}</td>')
                    # delete the file
                    links.append(
                        f'<td><button onclick="deleteFile(\'{web_path}/{entry.name}\')"><img src="{delete_icon_path}" width="25" height="25">\
                                    <span class="button-text">Delete</span>\
                                    </button></td></tr>')
        html_content += '\n'.join(links)
        html_content += """
        </ul>
        </body>
        </html>
        """
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

    Logger.info('Server started at {}:{}'.format(args.ip, args.port))

    while True:
        try:
            server_socket.listen(10000)
            client_socket, addr = server_socket.accept()  # accept the connection, addr is the address bound to the socket on the other end of the connection, including the port number and IP address
            # create a new thread to handle the request
            thread = HttpServer(client_socket, addr)
            Logger.info('{} get a connection from {}.'.format(thread.name, addr))
            thread.start()

        except Exception as e:
            Logger.error('Exception: {}'.format(e))
            traceback.print_exc()

        # finally:
        #     server_socket.close()
        #     print('Server closed')


if __name__ == '__main__':
    main()
