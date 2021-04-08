import ftp_util
import time
import logging
import yaml


PROXY_HEARTBEAT_TIMEOUT = 300       # 5 minutes


def is_proxy_descriptor(filename):
    """Returns true if filename is that of a proxy descriptor file.  Else false.
    Since proxy descriptor file names are just a negative number, calling function
    already knows the proxy ID number from the filename"""
    try:
        if int(filename) < 0:
            return True     # must be a negative integer
    except Exception as e:
        logging.debug("error processing possible proxy descriptor filename {}: {}".format(filename, e))
    return False


def parse_proxy_descriptor(data):
    """Pass in raw data from file.  Returns public key and heartbeat. Returns None
    for both values if file has an invalid formatting"""
    try:
        if isinstance(data, (bytes, bytearray)):
            data = data.decode()
        d = yaml.load(data)
        return d['key'], int(d['heartbeat'])
    except Exception as e:
        logging.debug("error processing proxy descriptor file {}: {}".format(filename, e))
        return None, None


def generate_proxy_descriptor(key):
    """Given the proxy's public key, return the binary data to write to the
    proxy descriptor file."""
    d = {'key':key._public_key, 'heartbeat':int(time.time())}
    return yaml.dump(d).encode()

