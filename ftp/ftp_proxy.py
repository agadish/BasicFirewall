#!/usr/bin/env python3

import urllib.parse
import proxy_server

FTP_PROXY_PORT = 210


class FTPClientHandler(proxy_server.ClientHandler):
    def handle_client_request(self):
        print('handle_client_request!')
        data = self.client_socket.recv(1024 * 1024)
        if not data:
            # Connection is closed
            self.unregister_from_reactor()
        # XXX: We assume no fragmentation
        self.server_socket.send(data)

    def handle_server_response(self):
        print('handle_server_response!')
        try:
            response = ftp.client.FTPResponse(self.server_socket)
            response.begin()
            data = response.read()
        except Exception as e:
            # Connection is closed
            print('Break by exception %s' % (e, ))
            self.unregister_from_reactor()

        if not response:
            self.unregister_from_reactor()

        self.client_socket.send(response)


class FTPProxy(proxy_server.ProxyServer):
    def __init__(self, listen_port=FTP_PROXY_PORT):
        super(FTPProxy, self).__init__(listen_port)

    def create_client_handler(self, connection_entry):
        return FTPClientHandler(connection_entry)


def main():
    proxy = FTPProxy()
    proxy.run_forever()


if __name__ == '__main__':
    exit(main())
