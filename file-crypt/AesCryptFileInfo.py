import os
import time
import hmac

class AESFileCryptInfo:
    VERSION = b'\x10\x00\x00\x55'
    VERSION_SIZE        = 4
    TIMESTAMP_SIZE      = 8
    IV_SIZE             = 128//8
    HMAC_SIZE           = 32
    
    VERSION_1_OFFSET    = 0
    TIMESTAMP_OFFSET    = VERSION_1_OFFSET + VERSION_SIZE
    IV_OFFSET           = TIMESTAMP_OFFSET + TIMESTAMP_SIZE
    HMAC_OFFSET         = IV_OFFSET + IV_SIZE
    VERSION_2_OFFSET    = HMAC_OFFSET + HMAC_SIZE
    HEADER_SIZE         = VERSION_2_OFFSET + VERSION_SIZE
    
    _key = None
    _iv = None
    _hmac = None
    _timestamp = None
    
    # Initialize newly created AESFileCryptInfo object
    #   `key` is the bytearray containing the AES key; it must be 
    #       writeable if AESFileCryptInfo.destroy_key() is to be run
    #   `iv` is the AES IV to use; if this is None, a random 128-bit
    #       Nonce will be generated 
    #   `timestamp` is a bytes-like timestamp (epoch time); 
    #       if this is None, the current time will be used 
    def __init__(self, key, iv=None, timestamp=None):
        # Copy key reference to object
        #print('__init__ key id = %X' % id(key))
        self._key = key
        #print('__init__ self.key id = %X' % id(self._key))
        
        # Create IV or use input value 
        if iv is None:
            self._iv = os.urandom(self.IV_SIZE)
        else:
            if len(iv) != self.IV_SIZE:     raise ValueError
            self._iv = bytes(iv)
        
        # Create timestamp or use input value 
        if timestamp is None:
            timestamp = int(time.time())
            self._timestamp = timestamp.to_bytes(
                self.TIMESTAMP_SIZE, 'little')
        else:
            if len(timestamp) != self.TIMESTAMP_SIZE: raise ValueError
            self._timestamp = bytes(timestamp)
            
        # Create HMAC obj for encrypted data to be passed through
        self._hmac = hmac.new(self._key, digestmod='sha256')
        
    # Class accessor functions
    def get_iv(self):
        return self._iv
    def get_hmac_digest(self):
        return self._hmac.digest()
    def get_timestamp(self):
        return self._timestamp
       
    # Create bytes to be appended to file 
    # Header format:
    # Offset:   0-3        4-11    12-27  28-59     60-63
    #       ------------------------------------------------
    # Field | Version | Timestamp |  IV  | HMAC |  Version |
    #       ------------------------------------------------
    # Size       4          8        16     32        4
    # Field descriptions:
    #   `Version` is 4-byte version value (for this version, it is 
    #       hex 10 00 00 55)
    #       This field is present at end of message for forward 
    #       compatibitility
    #   `Timestamp` is the timestamp when this object was created
    #       (formatted as little endian) 
    #   `HMAC` is the HMAC of the data processed (ciphertext of 
    #       message + version + timestamp + iv) 
    def pack_header_bytes(self):
        timestamp_bytes = self._timestamp
        iv_bytes = self._iv
        hmac_bytes = self._hmac.digest()
        version_bytes = self.VERSION
        
        header = b'' + version_bytes + timestamp_bytes + iv_bytes + \
                 hmac_bytes + version_bytes
        return header
    
    # Returns header bytes needed for HMAC authentication
    def pack_hmac_bytes(self):
        timestamp_bytes = self._timestamp
        iv_bytes = self._iv
        version_bytes = self.VERSION
        return b'' + version_bytes + timestamp_bytes + iv_bytes
    
    # Create new AESFileCryptInfo obj from a given header
    # Input:
    #   `header` is a bytes-like object
    # Output:
    #   Returns AESFileCryptInfo object with header info
    @classmethod
    def from_header_bytes(cls, header, key):
        version_bytes_1 = header[cls.VERSION_1_OFFSET : 
            cls.VERSION_1_OFFSET+cls.VERSION_SIZE]
        timestamp_bytes = header[cls.TIMESTAMP_OFFSET : 
            cls.TIMESTAMP_OFFSET+cls.TIMESTAMP_SIZE]
        iv_bytes = header[cls.IV_OFFSET : 
            cls.IV_OFFSET+cls.IV_SIZE]
        hmac_bytes = header[cls.HMAC_OFFSET : 
            cls.HMAC_OFFSET+cls.HMAC_SIZE]
        version_bytes_2 = header[cls.VERSION_2_OFFSET : 
            cls.VERSION_2_OFFSET+cls.VERSION_SIZE]
            
        if version_bytes_1 != AESFileCryptInfo.VERSION:
            raise ValueError('Bad version field #1')
        if version_bytes_2 != AESFileCryptInfo.VERSION:
            raise ValueError('Bad version field #2')
        
        return (AESFileCryptInfo(
                    key,
                    iv=iv_bytes, 
                    timestamp=timestamp_bytes), 
                hmac_bytes)
            
    # Update context object as messages are processed 
    # This function only updates the HMAC variable with the new msg
    def update(self, msg):
        self._hmac.update(msg)
        #print('\tDigest is now %s' % \
        #    (repr(self._hmac.digest()[:4]) + '...'))
        
    # Compare stored HMAC digest with provided `hmac_digest` bytes
    def compare_hmac(self, hmac_digest):
        return hmac.compare_digest(self._hmac.digest(), hmac_digest)
    
    # Writes over key value with zeros
    def destroy_key(self):
        for i in range(len(self._key)):
            key[i] = 0

####################################################################
