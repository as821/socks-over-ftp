
from ftplib import FTP_TLS, all_errors, error_perm
from ftp_util import list_files, upload_binary_data, get_file_contents
from tunnel_util import is_proxy_descriptor, parse_proxy_descriptor
import secretsocks
import logging
import sys
import time

import nacl.utils
from nacl.public import PrivateKey, SealedBox



class FTPSocksClient(secretsocks.Client):
    def __init__(self, server_addr, username, password, tunnel_dir):
        # basic set up
        super().__init__()
        self.addr = server_addr
        self.username = username
        self.password = password
        self.tunnel_dir = tunnel_dir

        self.proxy_id = None
        self.proxy_key = None
        self.session_key = None


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
            for f in files:
                if is_proxy_descriptor(f[0]):
                    # parse proxy descriptor file to see if its heartbeat is valid
                    key, heartbeat = parse_proxy_descriptor( get_file_contents(ftps, f[0]) )
                    if key is None and heartbeat is None:
                        continue

                    # validate heartbeat
                    if heartbeat + PROXY_HEARTBEAT_TIMEOUT < time.time():
                        continue

                    # accept the first proxy we find (not great for load balancing, but it works for now)
                    self.proxy_id = int(f[0])
                    self.proxy_key = key
                    break

            if self.proxy_id is None:
                logging.error("no valid proxies in tunnel directory")
                sys.exit(-1)

            # start tunnel handshake by writing initial file with session ID encrypted with proxy public key



    def send(self):
        pass

    def recv(self):
        pass

