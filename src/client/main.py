
from ftplib import FTP_TLS, all_errors, error_perm
from ftp_util import list_files, upload_binary_data, get_file_contents
from tunnel_util import is_proxy_descriptor, parse_proxy_descriptor, parse_tunnel_filename, PROXY_HEARTBEAT_TIMEOUT
import secretsocks
import logging
import sys
import time

import nacl.utils
import nacl.secret
from nacl.public import PublicKey, PrivateKey, SealedBox

CLIENT_POLL_FREQ = 5


class FTPSocksClient(secretsocks.Client):
    def __init__(self, server_addr, username, password, tunnel_dir):
        # basic set up
        print("Client started")
        sys.stdout.flush()
        super().__init__()
        self.addr = server_addr
        self.username = username
        self.password = password
        self.tunnel_dir = tunnel_dir

        self.proxy_id = None
        self.proxy_key = None
        self.session_key = None
        self.session_box = None
        self.session_id = None


        with FTP_TLS(server_addr, username, password) as ftps:
            # set up secure connection
            ftps.prot_p()

            # verify that tunnel_dir exists
            try:
                ftps.cwd(tunnel_dir)
            except all_errors:
                logging.error("tunnel directory does not exist")
                sys.exit(-1)

            # check for proxy descriptor files, determine max session ID
            print("Searching for proxies...")
            sys.stdout.flush()
            files = list_files(ftps)
            max_id = -1
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

                # parse session ID from tunnel files (used to determine session ID for this client)
                s_id, _, _seq = parse_tunnel_filename(f[0])
                if s_id is not None and s_id > max_id:
                    max_id = s_id

            # error if no proxies are available
            if self.proxy_id is None:
                logging.error("no valid proxies in tunnel directory")
                sys.exit(-1)

            # start tunnel handshake by writing file with session key encrypted with proxy public key
            print("Suitable proxy found")
            sys.stdout.flush()
            self.session_id = str(max_id + 1)
            self._generate_session_key()
            data = self._generate_handshake_file()
            filename = self.session_id + '_0_0'
            upload_binary_data(ftps, filename, data)

        # wait for proxy's ACK message
        start = time.time()
        print("Waiting for proxy ACK...")
        sys.stdout.flush()
        while not self._poll_ack_file():
            # check if proxy has timed out
            if time.time() > PROXY_HEARTBEAT_TIMEOUT + start:
                logging.error("proxy timed out before completing handshake")
                sys.exit(-1)
            time.sleep(CLIENT_POLL_FREQ)

        ### Tunnel is set up ###
        print("Tunnel set up (proxy id: {})".format(self.proxy_id))
        sys.stdout.flush()


    def send(self):
        pass

    def recv(self):
        pass



    def _generate_session_key(self):
        """Create session key and a box initialized with the key"""
        self.session_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.session_box = nacl.secret.SecretBox(self.session_key)


    def _generate_handshake_file(self):
        """Returns bytes to be written to the handshake file.
        Encrypts the generated session key with the proxy's public key"""
        return SealedBox(PublicKey(self.proxy_key)).encrypt(self.session_key)



    def _is_ack_file(self, ftps, filename):
        """Return True if filename is an ACK file from the proxy (part of the handshake.
        Checks if filename is proper formatting, if so, decrypts and checks contents with session key"""
        a, b, c = parse_tunnel_filename(filename)
        if a is not None and a == int(self.session_id) and b == 1 and c == 0:
            try:
                # attempt to decrypt file contents with the session key
                plaintext = self.session_box.decrypt(get_file_contents(ftps, filename))
                if plaintext == b"ACK":
                    return True
            except Exception as e:
                return False
        return False



    def _poll_ack_file(self):
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
                if self._is_ack_file(ftps, f[0]):
                    return True
        return False


if __name__ == '__main__':
    client = FTPSocksClient('127.0.0.1', 'user', '12345', '/')