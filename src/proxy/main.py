
from ftplib import FTP_TLS, all_errors, error_perm
from ftp_util import list_files, upload_binary_data, get_file_contents
from tunnel_util import is_proxy_descriptor, generate_proxy_descriptor, parse_tunnel_filename, PROXY_HEARTBEAT_TIMEOUT
import secretsocks
import logging
import sys
import time

import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, SealedBox


PROXY_POLL_FREQ = 5    # TODO should increase this, is just small for testing


class FTPSocksProxy(secretsocks.Client):
    def __init__(self, server_addr, username, password, tunnel_dir, pub_file=None, priv_file=None):
        # basic set up
        print("Proxy started")
        sys.stdout.flush()
        super().__init__()
        self.addr = server_addr
        self.username = username
        self.password = password
        self.tunnel_dir = tunnel_dir

        self.heart = -1
        self.my_proxy_id = None
        self.session_key = None
        self.session_box = None
        self.public_key = None
        self.private_key = None
        self.client_id = None

        self.outgoing_seq = 0
        self.incoming_seq = 0

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


        with FTP_TLS(server_addr, username, password) as ftps:
            # set up secure connection
            ftps.prot_p()

            # verify that tunnel_dir exists
            try:
                ftps.cwd(tunnel_dir)
            except all_errors:
                logging.error("tunnel directory does not exist")
                sys.exit(-1)

            # check for proxy descriptor files
            files = list_files(ftps)
            _min = 0        # all proxy descriptor filenames < 0
            for f in files:
                if is_proxy_descriptor(f[0]) and int(f[0]) < _min:
                    _min = int(f[0])

            # create proxy descriptor file for this proxy
            self.my_proxy_id = _min - 1
            upload_binary_data(ftps, self.my_proxy_id, generate_proxy_descriptor(self.public_key))
            self.heart = time.time()

        # only have to support a single client per proxy, so just poll here until a client connects
        print("Awaiting a client connection...")
        sys.stdout.flush()
        while self.client_id is None:
            time.sleep(PROXY_POLL_FREQ)
            self._poll_handshake_file()

        # create ACK file
        with FTP_TLS(server_addr, username, password) as ftps:
            # set up secure connection
            ftps.prot_p()

            # verify that tunnel_dir exists
            try:
                ftps.cwd(tunnel_dir)
            except all_errors:
                logging.error("tunnel directory does not exist")
                sys.exit(-1)

            # create ACK file
            upload_binary_data(ftps, str(self.client_id) + "_1_0", self._encrypt_data(b"ACK"))

        ### Tunnel is set up, wait for client transmissions ###
        print("Tunnel setup (session ID: {})".format(self.client_id))
        sys.stdout.flush()



    def send(self):
        pass

    def recv(self):
        pass


    def _poll_handshake_file(self):
        """Check if a client has created a handshake file.  If so, parse the file and store
        the session key"""
        with FTP_TLS(self.addr, self.username, self.password) as ftps:
            # set up connection
            ftps.prot_p()
            try:
                ftps.cwd(self.tunnel_dir)
            except all_errors:
                logging.error("tunnel directory does not exist")
                sys.exit(-1)

            # check for file with valid name
            files = list_files(ftps)
            for f in files:
                s_id, direction, seq = parse_tunnel_filename(f[0])
                if s_id is not None and direction == 0 and seq == 0:
                    # check if contents of file is encrypted with this proxy's public key
                    data = get_file_contents(ftps, f[0])
                    try:
                        # attempt to decrypt the received message
                        unseal_box = SealedBox(self.private_key)
                        self.session_key = unseal_box.decrypt(data)
                        self.client_id = s_id
                        self.session_box = nacl.secret.SecretBox(self.session_key)
                        return
                    except Exception as e:
                        # file contents not encrypted with proxy's key
                        continue

            # update heartbeat if needed
            if self.heart + PROXY_HEARTBEAT_TIMEOUT < time.time():
                upload_binary_data(ftps, self.my_proxy_id, generate_proxy_descriptor(self.public_key))
                self.heart = time.time()


    def _encrypt_data(self, data):
        """Encrypt data with the session key"""
        return self.session_box.encrypt(data)




if __name__ == '__main__':
    proxy = FTPSocksProxy('127.0.0.1', 'user', '12345', '/')