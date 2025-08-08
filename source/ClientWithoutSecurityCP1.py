import base64
import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
import zipfile
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from translations import translations


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")

def encrypt_file_in_blocks_oaep(filename, public_key):
    """
    Encrypts file data in blocks using RSA with OAEP padding
    Max data block size: 62 bytes (128 - 66 padding bytes)
    """
    BLOCK_SIZE = 62  # Maximum data size per block with OAEP padding
    
    encrypted_blocks = []
    zip_file = "data.zip"

    with zipfile.ZipFile(zip_file,"w",compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(filename)
    
    # Read and encrypt file in blocks
    with open(zip_file, mode="rb") as fp:

        while True:
                # Read a block of data
            data_block = fp.read(BLOCK_SIZE)
                
            if not data_block:
                break  # End of file
                
                # Encrypt the block using RSA with OAEP padding
            encrypted_block = public_key.encrypt(
                data_block,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )
                
                # Each encrypted block will be exactly 128 bytes (1024 bits)
            encrypted_blocks.append(encrypted_block)

        print(_("Original File Size") + f"{os.path.getsize(filename)} bytes")
        print(_("Zipped File Size") + f"{os.path.getsize("data.zip")} bytes")
    
    return [encrypted_blocks, os.path.getsize("data.zip")]



def print_progress_bar(current, total, bar_length=40):
    percent = current / total
    filled_length = int(bar_length * percent)
    bar = '=' * filled_length + ' ' * (bar_length - filled_length)
    sys.stdout.write(_("Progress") + f'[{bar}] {percent*100:.1f}%')
    sys.stdout.flush()

def select_language(supported_languages=None):
    if supported_languages is None:
        supported_languages = ['en', 'zh']

    print("Select your language:")
    for idx, code in enumerate(supported_languages, 1):
        print(f"{idx}. {code}")

    while True:
        choice = input("Enter number or language code (e.g. 1 or 'en'): ").strip().lower()
        print()


        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(supported_languages):
                return supported_languages[idx]
        elif choice in supported_languages:
            return choice

        print("Invalid input. Please try again.")

def _(text):
    return translations.get(lang, {}).get(text, text)


lang = select_language()



def main(args):

    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"
    start_time = time.time()

    # try:
    print(_("Establishing Connection"))
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print(_("Connected"))
        print("Generating auth message...", flush=True)

        nonce = secrets.token_bytes(32) # we are sending a nonce to ensure that server is alive
        
        timestamp_int = int(datetime.now().timestamp())

        # pack timestamp int as 8-byte big endian
        timestamp_bytes = timestamp_int.to_bytes(8, 'big')
        
        nonce_message = nonce + timestamp_bytes
        print(_("Sending Mode 3"), flush=True)
        s.sendall(convert_int_to_bytes(3))
        print(_("Sent Mode 3"), flush=True)
        s.sendall(convert_int_to_bytes(len(nonce_message)))
        s.sendall(nonce_message)

        #ACCEPTING SIGNED NONCE FROM SERVER
        m1_bytes_signed = s.recv(8)
        signed_len = convert_bytes_to_int(m1_bytes_signed)
        signed_message = b""
        while len(signed_message) < signed_len:
            signed_message += s.recv(signed_len-len(signed_message))
        
        #ACCEPTING SERVER SIGNED CERT
        
        m1_bytes_cert = s.recv(8)
        cert_len = convert_bytes_to_int(m1_bytes_cert)
        server_cert_raw = b""
        while len(server_cert_raw) < cert_len:
            server_cert_raw += s.recv(cert_len-len(server_cert_raw))
        
        try:
            #GET PUBLIC KEY FROM CACSERTIFICATE.CRT, SHOULD BE PUBLIC KNOWLEDGE ALREADY
            with open("source/auth/cacsertificate.crt","rb") as f:
                ca_cert_raw = f.read()
                ca_cert = x509.load_pem_x509_certificate(
    data=ca_cert_raw, backend=default_backend()
)
                ca_public_key = ca_cert.public_key()
                #VERIFY SERVER CERT THAT WE RECEIVED
                server_cert = x509.load_pem_x509_certificate(data=server_cert_raw, backend=default_backend())

                ca_public_key.verify(
                    signature=server_cert.signature, # signature bytes to  verify
                    data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
                    padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
                    algorithm=server_cert.signature_hash_algorithm,
                )
                print(_("Auth Success") + "\n")
                server_public_key = server_cert.public_key()
                #assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
                
                #DECRYPTION OF NONCE MESSAGE
                server_public_key.verify(signed_message,nonce_message,
                    padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                    )
                
                
        except InvalidSignature:
            print(_("Auth Failure"))
            s.sendall(convert_int_to_bytes(2))
            return
        except Exception as e:
            print(_("Auth Error"), e)
            traceback.print_exc()
            s.sendall(convert_int_to_bytes(2))
            return

        print(_("Server Authenticated") + "\n")
        
        
        
        while True:
            filename = input(_("Enter File")).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input(_("Invalid File")).strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            #Encrypt this part under CP1
            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                encrypted_blocks,original_file_size = encrypt_file_in_blocks_oaep(filename, server_public_key)
                encrypted_filename = "enc_"+filename.split("/")[-1]
            
            with open(f"send_files_enc/{encrypted_filename}", mode="wb") as fp:
                for block in encrypted_blocks:
                    fp.write(block)
            
            print(_("Encrypted File Saved"))
            
                # Send encrypted file data (MODE = 1)
            s.sendall(convert_int_to_bytes(1))  
            s.sendall(convert_int_to_bytes(original_file_size))  # M1 = original file size
            total_bytes = original_file_size
            bytes_sent = 0
            block_data_size = 62
                
                # Send each encrypted block
            for encrypted_block in encrypted_blocks:
                s.sendall(encrypted_block)  # M2 = encrypted file data blocks (128 bytes each)
                bytes_sent += block_data_size
                if bytes_sent > total_bytes:
                    bytes_sent = total_bytes  # Clamp to total in case of partial last block
                print_progress_bar(bytes_sent, total_bytes)

            print()    
            print(_("Sent File") +  f"{len(encrypted_blocks)}" + _("Encrypted blocks") + f"{original_file_size} bytes")
            # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print(_("Closing Connection"))

    end_time = time.time()
    print(_("Program Run Time") + f"{end_time - start_time}s")


if __name__ == "__main__":
    
    main(sys.argv[1:])
