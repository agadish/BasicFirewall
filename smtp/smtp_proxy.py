#!/usr/bin/env python3

import sys
sys.path.append('..')
import proxy.proxy_server
import proxy.dlp
import re
import itertools

SMTP_PROXY_PORT = 250


class SMTPClientHandler(proxy.proxy_server.ClientHandler):
    def __init__(self, *args, **kwargs):
        super(SMTPClientHandler, self).__init__(*args, **kwargs)
        self.request = b''

    def handle_client_request(self):
        current_data = self.client_socket.recv(1024 * 1024)
        if not current_data:
            # Connection is closed
            self.close()
            return
        self.request += current_data
        if proxy.dlp.is_bad_request(self.request.decode('utf-8')):
            self.close()
        else:
            self.server_socket.sendall(current_data)

    def handle_server_response(self):
        current_data = self.server_socket.recv(1024 * 1024)
        if not current_data:
            # Connection is closed
            self.close()
            return
        self.client_socket.sendall(current_data)



class SMTPProxy(proxy.proxy_server.ProxyServer):
    def __init__(self, listen_port=SMTP_PROXY_PORT):
        super(SMTPProxy, self).__init__(listen_port)

    def create_client_handler(self, connection_entry):
        return SMTPClientHandler(connection_entry)


def main():
    proxy = SMTPProxy()
    proxy.run_forever()


if __name__ == '__main__':
    exit(main())
