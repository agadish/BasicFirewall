#!/usr/bin/env python3

#  import urllib.parse
import http
import proxy_server
from email.parser import BytesParser

HTTP_PROXY_PORT = 800
CONTENT_TYPE = 'Content-Type'
REJECTED_CONTENT_TYPES = ['text/csv', 'application/zip']


class HTTPClientHandler(proxy_server.ClientHandler):
    def __init__(self, *args, **kwargs):
        super(HTTPClientHandler, self).__init__(*args, **kwargs)
        self.response = b''

    def handle_client_request(self):
        # XXX: We assume no fragmentation
        data = self.client_socket.recv(1024 * 1024)
        if not data:
            # Connection is closed
            self.close()
            return
        self.server_socket.sendall(data)

    def handle_server_response(self):
        # XXX: We assume no fragmentation
        current_data = self.server_socket.recv(1024 * 1024)
        if not current_data:
            # Connection is closed
            self.close()
            return
        self.response += current_data
        if self.is_bad_response():
            self.close()
        else:
            self.client_socket.sendall(current_data)

    def is_bad_response(self):
        try:
            response_line, headers_alone = self.response.split(b'\r\n', 1)
            headers = BytesParser().parsebytes(headers_alone)
            if CONTENT_TYPE in headers:
                if headers[CONTENT_TYPE] in REJECTED_CONTENT_TYPES:
                    print('HTTP Proxy blocked response with %s of %s' % (CONTENT_TYPE, headers[CONTENT_TYPE], ))
                    return True
                else:
                    print('headers[CONTENT_TYPE]="%s" is OK' % (headers[CONTENT_TYPE], ))

        except Exception as e:
            print('Error parsing HTTP response: %s' % (e, ))

        return False


class HTTPProxy(proxy_server.ProxyServer):
    def __init__(self, listen_port=HTTP_PROXY_PORT):
        super(HTTPProxy, self).__init__(listen_port)

    def create_client_handler(self, connection_entry):
        return HTTPClientHandler(connection_entry)


def main():
    proxy = HTTPProxy()
    proxy.run_forever()


if __name__ == '__main__':
    exit(main())
