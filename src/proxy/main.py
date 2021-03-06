import argparse
import logging
import sys
import time
import threading

from ftplib import FTP, FTP_TLS, all_errors, error_perm
from ftp_util import list_files, upload_binary_data, get_file_contents, delete_file
from tunnel_util import is_proxy_descriptor, generate_proxy_descriptor, parse_tunnel_filename, PROXY_HEARTBEAT_TIMEOUT, CLIENT_TIMEOUT
import secretsocks

import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, SealedBox

# from secretsocks example
PY3 = False
if sys.version_info[0] == 3:
    import queue as Queue
    PY3 = True
else:
    import Queue
    range = xrange


PROXY_POLL_FREQ = 5    # TODO should increase this, is just small for testing


class FTPSocksProxy(secretsocks.Server):
    def __init__(self, server_addr, username, password, use_plain, tunnel_dir, pub_file=None, priv_file=None):
        # basic set up
        print("Proxy started")
        sys.stdout.flush()
        super().__init__()
        self.addr = server_addr
        self.username = username
        self.password = password
        self.use_plain = use_plain
        self.tunnel_dir = tunnel_dir

        self.heart = -1
        self.my_proxy_id = None
        self.session_key = None
        self.session_box = None
        self.public_key = None
        self.private_key = None
        self.session_id = None

        self.last_recv = -1
        self.outgoing_seq = 0
        self.incoming_seq = 0
        self.alive = True
        self.alive_lock = threading.Lock()
        self.ftp_account_lock = threading.Lock()    # avoid simultaneous logins with same credentials
        self.xmit_lock = threading.Lock()    # avoid simultaneous logins with same credentials

        # process keyfile
        if pub_file is not None:
            if priv_file is not None:
                # TODO
                raise NotImplementedError("specifying public/private key used by proxy is not yet supported")
            else:
                logging.error("need both public and private key files")
                sys.exit(-1)
        elif priv_file is not None:
            logging.error("need both public and private key files")
            sys.exit(-1)

        # generate public/private key pair if no keys are specified
        if self.public_key is None and self.private_key is None:
            self.private_key = PrivateKey.generate()
            self.public_key = self.private_key.public_key

        # check for proxy descriptor files
        self.ftps = self._login_ftp()
        files = list_files(self.ftps)
        _min = 0        # all proxy descriptor filenames < 0
        for f in files:
            if is_proxy_descriptor(f[0]) and int(f[0]) < _min:
                _min = int(f[0])

        # create proxy descriptor file for this proxy
        self.my_proxy_id = _min - 1
        upload_binary_data(self.ftps, self.my_proxy_id, generate_proxy_descriptor(self.public_key))
        self.heart = time.time()

        # only have to support a single client per proxy, so just poll here until a client connects
        print("Awaiting a client connection...")
        sys.stdout.flush()
        while self.session_id is None:
            time.sleep(PROXY_POLL_FREQ)
            self._poll_handshake_file()

        # create ACK file
        self.incoming_seq += 1
        upload_binary_data(self.ftps, str(self.session_id) + "_1_0", self._encrypt_data(b"ACK"))
        self.outgoing_seq += 1

        ### Tunnel is set up, wait for client transmissions ###
        print("Tunnel setup (session ID: {})".format(self.session_id))
        self.last_recv = time.time()
        sys.stdout.flush()
        self.start()

    def recv(self):
        """"Receive data from the data channel and push it to the receive queue"""
        while self._am_i_alive():
            try:
                # check if there is a valid tunnel file to read
                data = None
                with self.xmit_lock:
                    files = list_files(self.ftps)
                    for f in files:
                        if self._is_next_inbound_packet(f[0]):
                            # get file contents
                            self.incoming_seq += 1
                            data = get_file_contents(self.ftps, f[0])
                            if data is None:
                                raise ValueError("get_file_contents returned None.  Check debugging output.")

                            # delete file
                            delete_file(self.ftps, f[0])
                            break

                # write received data to recvbuf
                if data is not None:
                    d = self._decrypt_data(data)
                    sys.stdout.flush()
                    self.recvbuf.put(d)
                    self.last_recv = time.time()

                # update heartbeat if needed
                elif self.heart + PROXY_HEARTBEAT_TIMEOUT < time.time():
                    with self.xmit_lock:
                        upload_binary_data(self.ftps, self.my_proxy_id, generate_proxy_descriptor(self.public_key))
                        self.heart = time.time()

                # check if connection has timed out
                if self.last_recv + CLIENT_TIMEOUT < time.time():
                    raise ValueError("client has timed out")

            except Exception as e:
                self._kill_self()
                logging.error("recv thread exception: {}".format(e))
        logging.info("recv thread exit")

    def write(self):
        """Take data from the write queue and send it over the data channel"""
        while self._am_i_alive():
            # read data from the write queue
            try:
                data = self.writebuf.get(timeout=10)
            except Queue.Empty:
                continue

            # send data over channel (write to file with appropriate name
            with self.xmit_lock:
                try:
                    upload_binary_data(self.ftps, str(self.session_id) + "_1_" + str(self.outgoing_seq), self._encrypt_data(data))
                    self.outgoing_seq += 1
                except Exception as e:
                    self._kill_self()
                    logging.error("write thread exception: {}".format(e))
        logging.info("write thread exit")

    def _poll_handshake_file(self):
        """Check if a client has created a handshake file.  If so, parse the file and store
        the session key"""
        # check for file with valid name
        with self.xmit_lock:
            files = list_files(self.ftps)
            for f in files:
                s_id, direction, seq = parse_tunnel_filename(f[0])
                if s_id is not None and direction == 0 and seq == 0:
                    # check if contents of file is encrypted with this proxy's public key
                    data = get_file_contents(self.ftps, f[0])
                    try:
                        # attempt to decrypt the received message
                        unseal_box = SealedBox(self.private_key)
                        self.session_key = unseal_box.decrypt(data)
                        self.session_id = s_id
                        return
                    except Exception as e:
                        # file contents not encrypted with proxy's key
                        continue

            # update heartbeat if needed
            if self.heart + PROXY_HEARTBEAT_TIMEOUT < time.time():
                upload_binary_data(self.ftps, self.my_proxy_id, generate_proxy_descriptor(self.public_key))
                self.heart = time.time()

    def _encrypt_data(self, data):
        """Encrypt data with the session key"""
        session_box = nacl.secret.SecretBox(self.session_key)
        return session_box.encrypt(data)


    def _decrypt_data(self, data):
        """Decrypt data with the session key"""
        session_box = nacl.secret.SecretBox(self.session_key)
        return session_box.decrypt(data)


    def _is_next_inbound_packet(self, filename):
        """Return True if is the next packet we are waiting for"""
        a, b, c = parse_tunnel_filename(filename)
        if a is not None and a == int(self.session_id) and b == 0 and c == self.incoming_seq:
            return True
        return False



    def _am_i_alive(self):
        """Access method for alive member.  self.alive is edited/accessed in both
        write and recv functions, need to synchronize access to that variable"""
        self.alive_lock.acquire()
        state = self.alive
        self.alive_lock.release()
        return state


    def _kill_self(self):
        self.alive_lock.acquire()
        self.alive = False
        self.alive_lock.release()

    def _login_ftp(self):
        # set up secure connection
        self.ftp_account_lock.acquire()

        if self.use_plain:
            ftps = FTP(self.addr, self.username, self.password)
        else:
            ftps = FTP_TLS(self.addr, self.username, self.password)
            ftps.prot_p()

        # verify that tunnel_dir exists
        try:
            ftps.cwd(self.tunnel_dir)
        except all_errors:
            raise ValueError("tunnel directory does not exist")
        return ftps


    def _logout_ftp(self, ftps):
        ftps.quit()
        self.ftp_account_lock.release()

def main(args):
    secretsocks.set_debug(args.socks_debug)
    client = FTPSocksProxy(args.server_ipv4_addr,
                            args.username,
                            args.password,
                            args.use_plain,
                            'xfer')
    while client._am_i_alive():     # busy wait
        time.sleep(10)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("server_ipv4_addr")
    parser.add_argument("username")
    parser.add_argument("password")
    parser.add_argument("--use_plain", action="store_true", default=False)
    parser.add_argument("--socks-debug", action="store_true", default=False)
    return parser.parse_args()

if __name__ == '__main__':
    main(parse_args())
