#!/usr/bin/env python3

import urllib.parse
import proxy_server
import re
import socket
import struct

FTP_PROXY_PORT = 210

PORT_REQUEST_FORMAT = b'^PORT ([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)'
PORT_REQUEST_REGEX = re.compile(PORT_REQUEST_FORMAT)
CONNECTION_WRITE_PATH = proxy_server.CONNECTION_READ_PATH # '/sys/class/fw/conns/conns'
FTP_FILE_PORT = 20


class FTPClientHandler(proxy_server.ClientHandler):
    def _register_entry(self, entry_raw):
        with open(CONNECTION_WRITE_PATH, 'wb') as f:
            f.write(entry_raw)

    def hook_data(self, data):
        data_match = PORT_REQUEST_REGEX.match(data)
        if data_match:
            print('Found a port request: %s' % (data, ))
            ip1, ip2, ip3, ip4, port1, port2 = data_match.groups()

            listen_ip = b'.'.join([ip1, ip2, ip3, ip4]).decode('utf-8')
            print('listen_ip=%s'%(listen_ip, ))
            listen_port = int(port1) * 256 + int(port2)
            print('listen_port=%s' % (listen_port, ))
            listen_src = (socket.inet_aton(listen_ip), struct.pack('!H', listen_port), )
            dest_ip, _ = self._entry.dest_addr
            dest_port = FTP_FILE_PORT
            peer_addr = (socket.inet_aton(dest_ip), struct.pack('!H', dest_port), )
            entry_raw = b'%s%s%s%s' % (*listen_src, *peer_addr, )

            self._register_entry(entry_raw)

    def handle_client_request(self):
        data = self.client_socket.recv(1024 * 1024)
        self.hook_data(data)
        if not data:
            # Connection is closed
            self.close()
            return
        # XXX: We assume no fragmentation
        self.server_socket.sendall(data)

    def handle_server_response(self):
        data = self.server_socket.recv(1024 * 1024)
        if not data:
            self.close()
            return
        # XXX: We assume no fragmentation
        self.client_socket.send(data)

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
