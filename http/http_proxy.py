#!/usr/bin/env python3

import urllib.parse
import proxy_server

HTTP_PROXY_PORT = 800
CONTENT_TYPE = 'Content-Type'
REJECTED_CONTENT_TYPES = ['text/csv', 'application/zip']


class HTTPClientHandler(proxy_server.ClientHandler):
    def handle_client_request(self):
        data = self.client_socket.read()
        if not data:
            # Connection is closed
            self.unregister_from_reactor()
        # XXX: We assume no fragmentation
        self.server_socket.send(data)

    def handle_server_response(self):
        try:
            response = http.client.HTTPResponse(self.server_socket)
            response.begin()
            data = response.read()
        except Exception as e:
            # Connection is closed
            print('Break by exception %s' % (e, ))
            self.unregister_from_reactor()

        if not response:
            self.unregister_from_reactor()
        if CONTENT_TYPE in parsed_data:
            print(parsed_data[CONTENT_TYPE])
            if parsed_data[CONTENT_TYPE] in REJECTED_CONTENT_TYPES:
                # DROP
                self.unregister_from_reactor()
        else:
            self.client_socket.send(response)


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
