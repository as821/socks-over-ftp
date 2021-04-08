
from ftplib import FTP_TLS, all_errors, error_perm
from ftp_util import list_files, upload_binary_data, get_file_contents
from tunnel_util import is_proxy_descriptor, generate_proxy_descriptor
import secretsocks
import logging
import sys
import time

import nacl.utils
from nacl.public import PrivateKey, SealedBox



class FTPSocksProxy(secretsocks.Client):
    def __init__(self, server_addr, username, password, tunnel_dir, pub_file=None, priv_file=None):
        # basic set up
        super().__init__()
        self.addr = server_addr
        self.username = username
        self.password = password
        self.tunnel_dir = tunnel_dir

        self.my_proxy_id = None
        self.session_key = None
        self.public_key = None
        self.private_key = None

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




        # TODO how to listen for incoming connections?



    def send(self):
        pass

    def recv(self):
        pass





