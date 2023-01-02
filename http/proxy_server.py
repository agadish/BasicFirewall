#!/usr/bin/env python3

import socket
import select
import struct

LOCAL_ADDRESS = '127.0.0.1'
CONNECTION_READ_PATH = '/sys/class/fw/conns/conns'
BACKLOG = 50

class Reactor(object):
    def __init__(self):
        self._read_fds = list()
        self._read_handlers = dict()
        # No write or execute support

    def register_read(self, fd, handler):
        if fd not in self._read_fds:
            self._read_fds.append(fd)
        self._read_handlers[fd] = handler

    def unregister_read(self, fd):
        self._read_fds.remove(fd)
        del self._read_handlers[fd]

    def run_epoch(self):
        r_ready, _, _ = select.select(self._read_fds, [], [])
        print('selected stuff!')
        for r_fd in r_ready:
            try:
                self._read_fds[r_fd]()
            except Exception as e:
                print('Error: reactor handler failed - %s' % (e, ))


class ConnectionEntry(object):
    ENTRY_FORMAT = '!' + 'LHLHB' * 2
    def __init__(self, raw_entry):
        if len(raw_entry) != struct.calcsize(self.ENTRY_FORMAT):
            raise ValueError('entry has inapropriate length %d (need %d)' % (len(raw_entry), struct.calcsize(self.ENTRY_FORMAT),  ))
        fields = struct.unpack(self.ENTRY_FORMAT, raw_entry)
        source_addr, dest_addr = self.entry_to_address(fields)
        self._source_addr = source_addr
        self._dest_addr = dest_addr
        self.orig_socket = None
        self.peer_socket = None

    def entry_to_address(cls, entry):
        print(entry[0], type(entry[0]))
        saddr = socket.inet_ntoa(struct.pack('!L', entry[0]))
        sport = entry[1]
        daddr = socket.inet_ntoa(struct.pack('!L', entry[2]))
        dport = entry[3]
        return ((saddr, sport), (daddr, dport))

    def __repr__(self):
        return str(self)

    def __str__(self):
        return '%s -> %s' % (self._source_addr, self._dest_addr, )

    def __eq__(self, addr):
        return self._source_addr == addr or self._dest_addr == addr

    def get_peer(self, addr):
        if self._source_addr == addr:
            return self._dest_addr
        elif self._dest_addr == addr:
            return self._source_addr
        else:
            raise ValueError('conncetion has no addr %s' % (addr, ))

    @classmethod
    def read_entries(cls, path=CONNECTION_READ_PATH):
        with open(CONNECTION_READ_PATH, 'rb') as f:
            data = f.read()
            entry_length = struct.calcsize(cls.ENTRY_FORMAT)
            entries = [ConnectionEntry(data[i : i + entry_length])
                       for i in range(0, len(data), entry_length)]
            return entries


class ClientHandler(object):
    def __init__(self, connection_entry):
        self._entry = entry

    @property
    def client_socket(self):
        return self._entry.orig_socket

    @property
    def server_socket(self):
        return self._entry.peer_socket

    def register_to_reactor(self, reactor):
        reactor.register_read(self.client_socket.fileno(), self.handle_client_request)
        reactor.register_read(self.server_socket.fileno(), self.handle_server_response)
        self._reactor = reactor

    def uregister_from_reactor(self):
        reactor.unregister_read(self.client_socket.fileno())
        reactor.unregister_read(self.server_socket.fileno())

    def handle_client_request(self):
        raise NotImplementedError()

    def handle_server_response(self):
        raise NotImplementedError()


class ProxyServer(object):
    def __init__(self, listen_port, bind_addr=LOCAL_ADDRESS, backlog=BACKLOG):
        self._bind_addr = bind_addr
        self._listen_port = listen_port
        self._backlog = backlog
        self._socket = None
        self._is_listening = False
        self._connections = list()
        self._reactor = Reactor()

    def listen(self):
        s = socket.socket()
        s.bind((self._bind_addr, self._listen_port))
        s.listen(self._backlog)
        self._socket = s
        self._is_listening = True

    def close(self):
        self._socket = None
        self._is_listening = False

    def accept_client(self):
        # 1. Accept client
        client_socket, client_addr = self._socket.accept()

        # 2. Read entry information from sysfs
        entry = self.read_connection_entry(client_addr)
        if not entry:
            raise ValueError('Proxy: entry not found, make sure firewall.ko is insmod-ed')
        print('Proxy: got socket from %s' % (client_addr, ))

        # 3. Connect to peer
        entry.orig_socket = client_socket
        entry.peer_socket = socket.socket()
        try:
            print('Proxy: connecting to %s' % (entry.get_peer(), ))
            entry.peer_socket.connect(entry.get_peer())
        except Exception as e:
            print('ERROR connecting to peer: %s' % (e, ))
            client_socket.close()
            return

        # 4. Save client sockets
        entry.register_to_reactor(self._reactor)

    @classmethod
    def read_connection_entry(cls, addr):
        entries = ConnectionEntry.read_entries()
        for entry in entries:
            if addr in entry:
                return entry
        return None

    def run_forever(self):
        if not self._is_listening:
            self.listen()

        self._reactor.register_read(self._socket.fileno(), self.accept_client)
        while True:
            self._reactor.run_epoch()

    def create_client_handler(self, entry):
        raise NotImplementedError()
