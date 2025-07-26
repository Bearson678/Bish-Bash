import base64
import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


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
    
    # Read and encrypt file in blocks
    with open(filename, mode="rb") as fp:

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
    
    return encrypted_blocks



def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"
    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")
        print("Generating auth message...", flush=True)

        authentication_message = secrets.token_bytes(32)

        print("Sending mode 3...", flush=True)
        s.sendall(convert_int_to_bytes(3))
        print("Sent mode 3", flush=True)
        s.sendall(convert_int_to_bytes(len(authentication_message)))
        s.sendall(authentication_message)

        #ACCEPTING SIGNED MESSAGE FROM SERVER
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
            #GET PUBLIC KEY FROM CACSERTIFICATE.CRT
            with open("source/auth/cacsertificate.crt","rb") as f:
                ca_cert_raw = f.read()
                ca_cert = x509.load_pem_x509_certificate(
    data=ca_cert_raw, backend=default_backend()
)
                ca_public_key = ca_cert.public_key()
                #VERIFY SERVER CERT
                server_cert = x509.load_pem_x509_certificate(data=server_cert_raw, backend=default_backend())

                ca_public_key.verify(
                    signature=server_cert.signature, # signature bytes to  verify
                    data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
                    padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
                    algorithm=server_cert.signature_hash_algorithm,
                )
                print("[AUTH SUCCESS] Server identity verified.\n")
                server_public_key = server_cert.public_key()
                #assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
                
                #DECRYPTION OF AUTHENTICATED MESSAGE
                server_public_key.verify(signed_message,authentication_message,
                    padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                    )
                
                
        except InvalidSignature:
            print("[AUTH FAILURE] Signature verification failed. Aborting.")
            s.sendall(convert_int_to_bytes(2))
            return
        except Exception as e:
            print("[ERROR] Exception during authentication:", e)
            traceback.print_exc()
            s.sendall(convert_int_to_bytes(2))
            return

        print("starting to send client challenge to server...\n")
        
        
        #send client challenge to server
        challenge_len_bytes = s.recv(8)
        challenge_len = convert_bytes_to_int(challenge_len_bytes)
        server_challenge = b""
        while len(server_challenge)<challenge_len:
            server_challenge += s.recv(challenge_len-len(server_challenge))
            
        #Load client private key
        with open("source/auth/client_private_key.pem", "rb") as key_file:
            client_private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        
        
        signed_challenge = client_private_key.sign(server_challenge,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
            )
        
        s.sendall(convert_int_to_bytes(len(signed_challenge)))
        s.sendall(signed_challenge)
        
        with open("source/auth/client_signed.crt","rb") as f:
            client_cert = f.read()
            
        s.send(convert_int_to_bytes(len(client_cert)))
        s.sendall(client_cert)
        
        
        
        while True:
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            #Encrypt this part under CP
            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                original_file_size = len(data)
                encrypted_blocks = encrypt_file_in_blocks_oaep(filename, server_public_key)
            
                # Send encrypted file data (MODE = 1)
                s.sendall(convert_int_to_bytes(1))  
                s.sendall(convert_int_to_bytes(original_file_size))  # M1 = original file size
                
                # Send each encrypted block
                for encrypted_block in encrypted_blocks:
                    s.sendall(encrypted_block)  # M2 = encrypted file data blocks (128 bytes each)
                
                print(f"Sent file with {len(encrypted_blocks)} encrypted blocks, original size: {original_file_size} bytes")
            # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    
    main(sys.argv[1:])
