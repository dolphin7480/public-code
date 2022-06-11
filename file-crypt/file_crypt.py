# Encrypt a file in-place using 256-bit AES CTR mode
# Written by dolphin7480, June 2022

import os
import shutil
import hmac
import time
import cryptography.hazmat.primitives.ciphers as crypto_ciphers
import cryptography.hazmat.backends as crypto_backends
import traceback

import key          # for TEST_KEY
#print('global key id = %X' % id(key.TEST_KEY))

####################################################################

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
    FOOTER_SIZE         = VERSION_2_OFFSET + VERSION_SIZE
    
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
    # Footer format:
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
    def pack_footer_bytes(self):
        timestamp_bytes = self._timestamp
        iv_bytes = self._iv
        hmac_bytes = self._hmac.digest()
        version_bytes = self.VERSION
        
        footer = b'' + version_bytes + timestamp_bytes + iv_bytes + \
                 hmac_bytes + version_bytes
        return footer
    
    # Returns footer bytes needed for HMAC authentication
    def pack_hmac_bytes(self):
        timestamp_bytes = self._timestamp
        iv_bytes = self._iv
        version_bytes = self.VERSION
        return b'' + version_bytes + timestamp_bytes + iv_bytes
    
    # Create new AESFileCryptInfo obj from a given footer
    # Input:
    #   `footer` is a bytes-like object
    # Output:
    #   Returns AESFileCryptInfo object with footer info
    @classmethod
    def from_footer_bytes(cls, footer):
        version_bytes_1 = footer[cls.VERSION_1_OFFSET : 
            cls.VERSION_1_OFFSET+cls.VERSION_SIZE]
        timestamp_bytes = footer[cls.TIMESTAMP_OFFSET : 
            cls.TIMESTAMP_OFFSET+cls.TIMESTAMP_SIZE]
        iv_bytes = footer[cls.IV_OFFSET : 
            cls.IV_OFFSET+cls.IV_SIZE]
        hmac_bytes = footer[cls.HMAC_OFFSET : 
            cls.HMAC_OFFSET+cls.HMAC_SIZE]
        version_bytes_2 = footer[cls.VERSION_2_OFFSET : 
            cls.VERSION_2_OFFSET+cls.VERSION_SIZE]
            
        if version_bytes_1 != AESFileCryptInfo.VERSION:
            raise ValueError('Bad version field #1')
        if version_bytes_2 != AESFileCryptInfo.VERSION:
            raise ValueError('Bad version field #2')
        
        return (AESFileCryptInfo(
                    key.TEST_KEY,
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
            self._key[i] = 0


####################################################################

# Encrypts a file in place, appending a AESFileCryptInfo footer 
# Input:
#   `key` is the bytearray containing the AES key; it must be 
#       writeable if AESFileCryptInfo.destroy_key() is to be run
#   `filename` is the path to the unencrypted file to encrypt
#   `chunk_size` is the size in bytes of data to process at a time
#       This should be a multiple of the cipher block size
# Output:
#   Data in `filename` will be encrypted with AESFileCryptInfo 
#       footer appended 
def encrypt_file(key, filename, chunk_size=None):
    #print('encrypt_file key id = %X' % id(key))
    
    # Read footer data from end of the file to be encrypted
    with open(filename, 'rb') as f:
        f.seek(-AESFileCryptInfo.FOOTER_SIZE, 2)
        footer = f.read()
    # If an AESFileCryptInfo object can be created from footer, 
    #   assume this file is already encrypted and error out 
    try:
        footer_obj, _ = AESFileCryptInfo.from_footer_bytes(footer)
    except ValueError:
        pass
    else:
        raise ValueError('File already encrypted')
    
    # Encrypt file blocks in-place
    crypto_ctx = AESFileCryptInfo(key)
    backend = crypto_backends.default_backend()
    cipher = crypto_ciphers.Cipher(
                crypto_ciphers.algorithms.AES(key),
                crypto_ciphers.modes.CTR(crypto_ctx.get_iv()),
                backend=backend)
    encryptor = cipher.encryptor()
    
    with open(filename, 'rb+') as f:
        try:
            while True:
                file_pointer = f.tell()
                
                # Read data
                if chunk_size is None:
                    data = f.read()
                else:
                    data = f.read(chunk_size)
                if len(data) == 0:
                    break
                    
                # Encrypt data
                ciphertext = encryptor.update(data)
                crypto_ctx.update(ciphertext)
                
                # Write out data 
                f.seek(file_pointer, 0)
                f.write(ciphertext)
            
            # Finalize & write out footer
            remainder = encryptor.finalize()
            if len(remainder) != 0:     raise ValueError
            
            
        finally:    # Always write footer, even if error occurs
            footer_hmac_bytes = crypto_ctx.pack_hmac_bytes()
            crypto_ctx.update(footer_hmac_bytes)
            
            f.seek(0,2)
            footer = crypto_ctx.pack_footer_bytes()
            f.write(footer)


# Decrypts a file that was encrypted using encrypt_file()
# Output file is first written to a temp file in the same directory,
#   then copied over the original
# Input:
#   `key` is the bytearray containing the AES key; it must be 
#       writeable if AESFileCryptInfo.destroy_key() is to be run
#   `filename` is the path to the encrypted file to encrypt
#   `chunk_size` is the size in bytes of data to process at a time
#       This should be a multiple of the cipher block size
# Output:
#   Data in `filename` will be encrypted with AESFileCryptInfo 
#       footer appended 
def decrypt_file(key, filename, chunk_size=None):
    #print('decrypt_file key id = %X' % id(key))
    
    # Read footer data from end of the file to be decrypted
    with open(filename, 'rb') as f:
        f.seek(-AESFileCryptInfo.FOOTER_SIZE, 2)
        footer = f.read()
    crypto_ctx, hmac_digest = \
        AESFileCryptInfo.from_footer_bytes(footer)
    infile_data_size = \
        os.path.getsize(filename) - AESFileCryptInfo.FOOTER_SIZE
    
    # Decrypt file blocks into new file 
    backend = crypto_backends.default_backend()
    cipher = crypto_ciphers.Cipher(
                crypto_ciphers.algorithms.AES(key),
                crypto_ciphers.modes.CTR(crypto_ctx.get_iv()),
                backend=backend)
    decryptor = cipher.decryptor()

    output_file = filename + '~'
    while os.path.exists(output_file):
        output_file += '~'
    
    data_read_size = 0
    with    open(filename, 'rb') as infile, \
            open(output_file, 'wb') as outfile:
        all_data_read = False
        while not all_data_read:
            # Read data from block 
            if chunk_size is None:
                data = infile.read()
            else:
                data = infile.read(chunk_size)
            assert (len(data) != 0) # Should never be zero 
                                    # (Must read footer before EOF)
            
            # Handle EOF & reading footer 
            data_read_size += len(data)
            if data_read_size >= infile_data_size:
                all_data_read = True
                data = data[:infile_data_size-data_read_size]
            if len(data) == 0:
                break
            
            # Decrypt data 
            plaintext = decryptor.update(data)
            crypto_ctx.update(data)
            
            # Write out data
            outfile.write(plaintext)
            
    # Finalize and compare HMAC digest received with the one 
    #   computed (error out if they do not match)
    try:
        remainder = decryptor.finalize()
        if len(remainder) != 0:     raise ValueError
        
        footer_hmac_bytes = crypto_ctx.pack_hmac_bytes()
        crypto_ctx.update(footer_hmac_bytes)
        if not crypto_ctx.compare_hmac(hmac_digest):
            crypto_digest = crypto_ctx.get_hmac_digest()
            raise ValueError(
        'HMAC from footer (%s) ' % (repr(hmac_digest[:4])+'...') + \
        'does not match data (%s)' % (repr(crypto_digest[:4])+'...')
            )

        # If no error, copy temp file over input file
        os.remove(filename)
        os.rename(output_file, filename)
    
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)


# Test driver for encrypt/decrypt
# IN_FILE will be copied to ENC_FILE and encrypted, then copied 
#   to DEC_FILE and decrypted
def main():
    IN_FILE     = 'putty.exe'
    #ENC_FILE    = 'putty_encrypted.exe'
    #DEC_FILE    = 'putty_decrypted.exe'
    ENC_FILE = DEC_FILE = IN_FILE
    
    print('Encrypting...')
    try:
        shutil.copy(IN_FILE, ENC_FILE)
    except shutil.SameFileError:
        pass
    encrypt_file(key.TEST_KEY, ENC_FILE)
    
    print('Decrypting...')
    try:
        shutil.copy(ENC_FILE, DEC_FILE)
    except shutil.SameFileError:
        pass
    decrypt_file(key.TEST_KEY, DEC_FILE)
        
    
if __name__ == '__main__':
    try:
        main()
    except:
        traceback.print_exc()
        input()