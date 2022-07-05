# Encrypt a file in-place using 256-bit AES CTR mode
# Written by dolphin7480, June 2022

import os
import shutil
import hmac
import time
import cryptography.hazmat.primitives.ciphers as crypto_ciphers
import cryptography.hazmat.backends as crypto_backends
import traceback

from AesCryptFileInfo import AESFileCryptInfo
import key as key_module        # for TEST_KEY
#print('global key id = %X' % id(key_module.TEST_KEY))

####################################################################

# Write over the referenced key value with zeroes
def destroy_key(key):
    for i in range(len(key)):
        key[i] = 0


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
        f.seek(-AESFileCryptInfo.HEADER_SIZE, 2)
        footer = f.read()
    # If an AESFileCryptInfo object can be created from footer, 
    #   assume this file is already encrypted and error out 
    try:
        footer_obj, _ = AESFileCryptInfo.from_header_bytes(footer, key_module.TEST_KEY)
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
            footer = crypto_ctx.pack_header_bytes()
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
        f.seek(-AESFileCryptInfo.HEADER_SIZE, 2)
        footer = f.read()
    crypto_ctx, hmac_digest = \
        AESFileCryptInfo.from_header_bytes(footer, key_module.TEST_KEY)
    infile_data_size = \
        os.path.getsize(filename) - AESFileCryptInfo.HEADER_SIZE
    
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
    encrypt_file(key_module.TEST_KEY, ENC_FILE)
    
    print('Decrypting...')
    try:
        shutil.copy(ENC_FILE, DEC_FILE)
    except shutil.SameFileError:
        pass
    decrypt_file(key_module.TEST_KEY, DEC_FILE)
        
    
if __name__ == '__main__':
    try:
        main()
    except:
        traceback.print_exc()
        input()