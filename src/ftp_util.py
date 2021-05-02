
import io
import logging


def list_files(ftp):
    """Return list of files in the current working directory.
    Each list entry is a tuple (name, modification time string, file size in bytes)
    Modification date does not have year, we just get a string with format 'Apr 03 HH:mm'.
    Only operation we might care about involving modification time is != since it increases monotonically"""
    # get list of files
    files = []
    ftp.dir(files.append)

    # fix output to a format that is useful
    for f in range(len(files)):
        s = files[f].split()
        files[f] = (s[-1], " ".join(s[-4 : -1]), s[-5])
    return files



def upload_binary_data(ftp, file_name, data):
    """Upload binary data to the FTP server with the specified filename.
    Will overwrite any existing file with the specified name."""
    cmd = "STOR " + str(file_name)
    b = io.BytesIO(data)
    ftp.storbinary(cmd, b)



def get_file_contents(ftp, file_name):
    """If file exists in the current working directory, the contents of the
    file will be returned as binary data. Else, None will be returned."""
    try:
        # need a data type that provides a useful callback to pass to ftp.retrbinary
        byte_store = []
        ftp.retrbinary('RETR ' + file_name, byte_store.append)

        # reassemble and return bytes content of the file
        local_bytes = b''
        for i in byte_store:
            local_bytes += i
        return local_bytes
    except Exception as e:
        logging.debug("error downloading file {}: {}".format(filename, e))
        return None



def delete_file(ftp, filename):
    """If file exists in the current working directory, delete the file"""
    try:
        ftp.delete(filename)
    except Exception as e:
        logging.debug("error deleting file {}: {}".format(filename, e))




