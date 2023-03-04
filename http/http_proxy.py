#!/usr/bin/env python3

import http
import sys
sys.path.append('..')
import proxy.proxy_server
import proxy.dlp
from email.parser import BytesParser
import re
import urllib.parse

HTTP_PROXY_PORT = 800
CONTENT_TYPE = 'Content-Type'
REJECTED_CONTENT_TYPES = ['text/csv', 'application/zip']

def checkAjaxInput(ajax_input: str) -> bool:
    pattern = re.compile('[&;|$`]')
    if pattern.search(ajax_input):
        return False
    else:
        return True


class HTTPClientHandler(proxy.proxy_server.ClientHandler):
    def __init__(self, *args, **kwargs):
        super(HTTPClientHandler, self).__init__(*args, **kwargs)
        self.request = b''
        self.response = b''

    def handle_client_request(self):
        current_data = self.client_socket.recv(1024 * 1024)
        if not current_data:
            # Connection is closed
            self.close()
            return
        self.request += current_data
        if self.is_bad_request() or proxy.dlp.is_bad_request(self.request.decode('utf-8')):
            self.close()
        else:
            self.server_socket.sendall(current_data)

    def handle_server_response(self):
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

    def is_bad_request(self):
        print(self.request)
        print(type(self.request))
        try:
            request_line, headers_alone = self.request.split(b'\r\n', 1)
        except Exception as e:
            return False

        method, url_raw, http_version = request_line.split()
        url_parsed = urllib.parse.urlparse(url_raw)
        path = url_parsed.path

        # 1. Check if request sent to /app/options.py
        is_vulnerable_webpage = (b'/app/options.py' == path)
        if not is_vulnerable_webpage:
            print('bye url')
            return False

        # 2. Check for malicious params in url query
        url_query = url_parsed.query.decode('utf-8')
        if self.are_malicious_params(url_query):
            print('IGNORING: Malicious param in URL, closing connection')
            return False

        # 3. Check for malicious params in payload
        headers = BytesParser().parsebytes(headers_alone)
        payload = headers.get_payload()
        if self.are_malicious_params(payload):
            print('IGNORING: Malicious param in paylooad, closing connection')
            return False

        return False

    def are_malicious_params(self, params):
        parsed_params = urllib.parse.parse_qs(params)
        for bad_param_name in ['ipbackend', 'backend_server']:
            if bad_param_name in parsed_params:
                is_legal_input = checkAjaxInput(parsed_params[bad_param_name][0])
                if not is_legal_input:
                    return True

        return False

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


class HTTPProxy(proxy.proxy_server.ProxyServer):
    def __init__(self, listen_port=HTTP_PROXY_PORT):
        super(HTTPProxy, self).__init__(listen_port)

    def create_client_handler(self, connection_entry):
        return HTTPClientHandler(connection_entry)


def main():
    proxy = HTTPProxy()
    proxy.run_forever()


if __name__ == '__main__':
    exit(main())
