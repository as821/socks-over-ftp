
from ftplib import FTP_TLS, all_errors, error_perm
from ftp_util import list_files, upload_binary_data, get_file_contents, delete_file
from tunnel_util import is_proxy_descriptor, parse_proxy_descriptor, parse_tunnel_filename, PROXY_HEARTBEAT_TIMEOUT
import secretsocks
import logging
import sys
import time
import threading

# from secretsocks example
PY3 = False
if sys.version_info[0] == 3:
    import queue as Queue
    PY3 = True
else:
    import Queue
    range = xrange

import nacl.utils
import nacl.secret
from nacl.public import PublicKey, PrivateKey, SealedBox

CLIENT_POLL_FREQ = 5



class FTPSocksClient(secretsocks.Client):
    def __init__(self, server_addr, username, password, tunnel_dir):
        """Set up tunnel when this class is instantiated"""
        # basic set up
        print("Client started")
        sys.stdout.flush()
        super().__init__()
        self.alive = True
        self.alive_lock = threading.Lock()

        self.addr = server_addr
        self.username = username
        self.password = password
        self.tunnel_dir = tunnel_dir

        self.proxy_id = None
        self.proxy_key = None
        self.session_key = None
        self.session_id = None
        self.outgoing_seq = 0
        self.incoming_seq = 0
        self.heartbeat = -1



        with FTP_TLS(self.addr, self.username, self.password) as ftps:
            # set up secure connection
            ftps.prot_p()

            # verify that tunnel_dir exists
            try:
                ftps.cwd(self.tunnel_dir)
            except all_errors:
                logging.error("tunnel directory does not exist")
                sys.exit(-1)

            # check for proxy descriptor files, determine max session ID
            print("Searching for proxies...")
            sys.stdout.flush()
            files = list_files(ftps)
            max_id = -1
            for f in files:
                # parse session ID from tunnel files (used to determine session ID for this client)
                s_id, _, _seq = parse_tunnel_filename(f[0])
                if s_id is not None and s_id > max_id:
                    max_id = s_id

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
            self.outgoing_seq += 1

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
        self.incoming_seq += 1

        ### Tunnel is set up ###
        print("Tunnel set up (proxy id: {})".format(self.proxy_id))
        sys.stdout.flush()
        self.heartbeat = time.time()
        self.start()



    def recv(self):
        """Receive data from the data channel and push it to the receive queue"""
        while self._am_i_alive():
            try:
                # check if there is a valid tunnel file to read
                data = None
                with FTP_TLS(self.addr, self.username, self.password) as ftps:
                    # set up secure connection
                    ftps.prot_p()

                    # verify that tunnel_dir exists
                    try:
                        ftps.cwd(self.tunnel_dir)
                    except all_errors:
                        raise ValueError("tunnel directory does not exist")

                    # check files
                    files = list_files(ftps)
                    for f in files:
                        if self._is_next_inbound_packet(f[0]):
                            # get file contents
                            self.incoming_seq += 1
                            data = get_file_contents(ftps, f[0])
                            if data is None:
                                raise ValueError("get_file_contents returned None.  Check debugging output.")

                            # delete file
                            delete_file(ftps, f[0])
                            break

                # write received data to recvbuf
                if data is not None:
                    # decrypt data with session key
                    d = self._decrypt_data(data)
                    self.recvbuf.put(d)
                elif time.time()  > self.heartbeat + PROXY_HEARTBEAT_TIMEOUT:
                    # channel has timed out
                    raise ValueError("channel has timed out")
                time.sleep(CLIENT_POLL_FREQ)
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
            try:
                with FTP_TLS(self.addr, self.username, self.password) as ftps:
                    # set up secure connection
                    ftps.prot_p()

                    # verify that tunnel_dir exists
                    try:
                        ftps.cwd(self.tunnel_dir)
                    except all_errors:
                        raise ValueError("tunnel directory does not exist")

                    # create file
                    upload_binary_data(ftps, str(self.session_id) + "_0_" + str(self.outgoing_seq), self._encrypt_data(data))
                    self.outgoing_seq += 1
            except Exception as e:
                self._kill_self()
                logging.error("write thread exception: {}".format(e))
        logging.info("write thread exit")


    def _generate_session_key(self):
        """Create session key and a box initialized with the key"""
        self.session_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)



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
                if self._decrypt_data(get_file_contents(ftps, filename)) == b"ACK":
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




    def _is_next_inbound_packet(self, filename):
        """Return True if is the next packet we are waiting for"""
        a, b, c = parse_tunnel_filename(filename)
        if a is not None and a == int(self.session_id) and b == 1 and c == self.incoming_seq:
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



    def _encrypt_data(self, data):
        """Encrypt data with the session key"""
        session_box = nacl.secret.SecretBox(self.session_key)
        d =  session_box.encrypt(data)
        print(data)
        sys.stdout.flush()
        return d


    def _decrypt_data(self, data):
        """Decrypt data with the session key"""
        session_box = nacl.secret.SecretBox(self.session_key)
        return session_box.decrypt(data)



if __name__ == '__main__':
    secretsocks.set_debug(True)
    client = FTPSocksClient('127.0.0.1', 'user', '12345', '/')

    # Start the standard listener with our client
    print('Starting socks server on port 1080...')
    listener = secretsocks.Listener(client, host='127.0.0.1', port=1080)
    listener.wait()
