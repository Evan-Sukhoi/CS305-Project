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
        # get the request from the client
        request = self.client_socket.recv(1024).decode('utf-8')
        print('Request: {}'.format(request))

        # parse the request
        request = request.split('\r\n')
        request_line = request[0].split(' ')
        method = request_line[0]
        path = request_line[1]
        http_version = request_line[2]

        # handle the request
        if method == 'GET':
            self.handle_get(path)
        elif method == 'POST':
            self.handle_post(path, request[-1])
        else:
            self.handle_error(405, 'Method Not Allowed')

    def handle_get(self, path):
        # if the path is a directory, return the index.html file
        if os.path.isdir(path):
            path = os.path.join(path, 'index.html')

        # if the path is a file, return the file
        if os.path.isfile(path):
            self.handle_file(path)
        else:
            self.handle_error(404, 'Not Found')

    def handle_post(self, path, data):
        # if the path is a directory, return the index.html file
        if os.path.isdir(path):
            path = os.path.join(path, 'index.html')

        # if the path is a file, return the file
        if os.path.isfile(path):
            self.handle_file(path)
        else:
            self.handle_error(404, 'Not Found')

    def handle_file(self, path):
        # get the file extension
        extension = pathlib.Path(path).suffix

        # get the file size
        file_size = os.path.getsize(path)

        # get the file type
        file_type = mimetypes.types_map[extension]

        # get the file modification time
        file_time = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%a, %d %b %Y %H:%M:%S GMT')

        # send the response header
        response_header = '{} 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\n\r\n'.format('HTTP/1.1', file_size, file_type, file_time)
        self.client_socket.sendall(response_header.encode('utf-8'))

        # send the file
        with open(path, 'rb') as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                self.client_socket.sendall(data)

    def handle_error(self, code, message):
        # get the error page
        path = os.path.join('error', '{}.html'.format(code))

        # get the file size
        file_size = os.path.getsize(path)

        # get the file type
        file_type = mimetypes.types_map['.html']

        # get the file modification time
        file_time = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%a, %d %b %Y %H:%M:%S GMT')

        # send the response header
        response_header = '{} {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nLast-Modified: {}\r\n\r\n'.format('HTTP/1.1', code, message, file_size, file_type, file_time)
        self.client_socket.sendall(response_header.encode('utf-8'))

        # send the file
        with open(path, 'rb') as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                self.client_socket.sendall(data)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 8080)) # bind the socket to host and port

while True:
    server_socket.listen(5) # start listening for incoming connections, 5 is the max number of queued connections
    client_socket, addr = server_socket.accept() # accept the connection, addr is the address bound to the socket on the other end of the connection, including the port number and IP address
    print('Got a connection from {}'.format(addr))

    # create a new thread to handle the request
    thread = HttpServer(client_socket, addr)
    thread.start()
    print('Thread started')
    thread.join() # wait for the thread to finish
    print('Thread finished')
    client_socket.close() # close the socket