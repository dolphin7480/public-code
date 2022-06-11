# Encrypt a file in-place using 256-bit AES CTR mode
# Written by dolphin7480, June 2022

import os
import cryptography.hazmat.primitives.ciphers as crypto_ciphers
import cryptography.hazmat.backends as crypto_backends
from key import TEST_KEY as KEY
print('key id = %X' % id(TEST_KEY))

####################################################################

class AESFileCryptInfo:
    VERSION = b'\x10\x00\x00\x55'
    TIMESTAMP_SIZE      = 8
    IV_SIZE             = 16
    HMAC_SIZE           = 32
    VERSION_SIZE        = 4
    
    TIMESTAMP_OFFSET    = 0
    IV_OFFSET           = TIMESTAMP_OFFSET + TIMESTAMP_SIZE
    HMAC_OFFSET         = IV_OFFSET + IV_SIZE
    VERSION_OFFSET      = HMAC_OFFSET + HMAC_SIZE
    
    _filename = None
    _key = None
    _iv = None
    _hmac = None
    _timestamp = None
    _mode = None
    
    def __init__(self, filename, key, mode):
        # TODO: Check that file is not already encrypted
        #   If so, error out
        self._filename = filename
        
        # Copy key reference to object and generate nonce
        print('__init__ key id = %X' % id(key))
        self._key = key
        print('__init__ self.key id = %X' % id(self._key))
        self._iv = os.urandom(128//8)
        
        # Create timestamp 
        self._timestamp = int(time.time())
        
        # Create HMAC obj for encrypted data to be passed through
        self._hmac = hmac.new(key, digestmod='sha256')
        
        # Set mode to 'encrypt' or 'decrypt'
        if not mode in ('encrypt', 'decrypt'):
            raise ValueError('Invalid mode')
        self._mode = mode
        
        
    # Create bytes to be appended to file 
    # Footer format:
    # Offset:    0-7      8-27  28-59     60-63
    #       --------------------------------------
    # Field | Timestamp |  IV  | HMAC |  Version |
    #       --------------------------------------
    # Size        8        16     32        4
    # Field descriptions:
    #   `Version` is 4-byte version value (for this version, it is 
    #       hex 10 00 00 55)
    #       This field is present at end of message for forward 
    #       compatibitility
    #   `Timestamp` is the timestamp when this object was created
    #       (formatted as little endian) 
    #   `HMAC` is the HMAC of the data processed (streamed through
    #       encryption/decryption)
    def pack_footer_bytes(self):
        timestamp_bytes = self._timestamp.to_bytes(
            self.TIMESTAMP_SIZE, 'little')
        iv_bytes = self._iv.to_bytes(
            self.IV_SIZE, 'little')
        hmac_bytes = self._hmac.to_bytes(
            self.HMAC_SIZE, 'little')
        version_bytes = self.VERSION.to_bytes(
            self.VERSION_SIZE, 'little')
        
        footer = timestamp_bytes+iv_bytes+hmac_bytes+version_bytes
        return footer
        
    # 
    def from_footer_bytes(self, footer):
        


####################################################################

# Encrypt/decrypt bytes-like `data` with bytes-like AES key 
#   `key` and bytes-like `iv`
def _enc(data, key, iv):
    backend = crypto_backends.default_backend()
    cipher = crypto_ciphers.Cipher(
                crypto_ciphers.algorithms.AES(key),
                crypto_ciphers.modes.CTR(iv),
                backend=backend)
    encryptor = cipher.encryptor()
    output = encryptor.update(data) + encryptor.finalize()
        
    return output

# Convert LE byte data to integer
def _le_bytes_to_int(data):
    value = 0
    for i, byte in enumerate(data):
        value += byte << (8*i)
    return value



def main(IO_FILE):
    with open(IO_FILE, 'rb') as f:
        data = f.read()
        
    nonce_bytes = "b'" + ''.join(['\\x%02X' % x for x in NONCE]) + "'"
    print("Using nonce %s" % nonce_bytes)
    output = enc(data, KEY, NONCE)
    
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(output)
    print('Writing nonce to output file...')
    with open('nonce.txt', 'w') as f:
        f.write(nonce_bytes)
    input()
    
if __name__ == '__main__':
    IO_FILE = 'putty.exe'
    main(IO_FILE)