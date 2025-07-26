import base64
import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
from signal import signal, SIGINT
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


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            # Read the metadata
                            original_file_size = convert_bytes_to_int(read_bytes(client_socket, 8))
                            print(f"Original file size: {original_file_size} bytes")
                            
                            BLOCK_SIZE = 62
                            num_blocks = (original_file_size + BLOCK_SIZE-1)//BLOCK_SIZE
                            print(f"Expecting {num_blocks} blocks")
                            decrypted_data = b''
                            encrypted_file_data = b''  # Store encrypted data for saving
                            
                            for block_num in range(num_blocks):
                                print(f"Reading block {block_num + 1}/{num_blocks}")
                                
                                # Read one encrypted block (128 bytes)
                                encrypted_block = read_bytes(client_socket, 128)
                                encrypted_file_data += encrypted_block  # Store for encrypted file
                                
                                try:
                                    # Decrypt the block using OAEP
                                    decrypted_block = private_key.decrypt(
                                        encrypted_block,
                                        padding.OAEP(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None,
                                        )
                                    )
                                    decrypted_data += decrypted_block
                                except Exception as e:
                                        print(f"Error decrypting block {block_num}: {e}")
                                        break
                            decrypted_data = decrypted_data[:original_file_size]
                            recv_filename = "recv_" + filename.split("/")[-1]
                            with open(f"recv_files/{recv_filename}", mode="wb") as fp:
                                fp.write(decrypted_data)
                            
                            enc_filename = "enc_"+ filename.split("/")[-1]
                            
                            with open(f"recv_files_enc/{enc_filename}", mode="wb") as fp:
                                fp.write(encrypted_file_data)
                            
                            print(f"Successfully decrypted and saved: {recv_filename}")
                            print(f"Decrypted size: {len(decrypted_data)} bytes")
                            print(f"Finished receiving file in {(time.time() - start_time)}s!")
                            

                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break

                        case 3:
                            print("[MODE3] Starting authentication handshake...")

                            #READ THE MODE 3 GIVEN BY CLIENT

                            msg_len = convert_bytes_to_int(read_bytes(client_socket,8))
                            authentication_message = read_bytes(client_socket,msg_len)

                            #LOADING PRIVATE KEY
                            with open("source/auth/server_private_key.pem", mode="rb") as key_file:
                                private_key = serialization.load_pem_private_key(bytes(key_file.read()), password=None)
                                public_key = private_key.public_key()
                                
                            #SIGN MESSAGE WITH PSS 
                            signature = private_key.sign(
                                authentication_message,
                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH,),
                                hashes.SHA256(),
                            )
                            
                            #Send back signed message
                            client_socket.sendall(convert_int_to_bytes(len(signature)))
                            client_socket.sendall(signature)
                            
                            #Send back the server_signed.crt
                            with open("source/auth/server_signed.crt", "rb") as f:
                                cert_data = f.read()
                            client_socket.sendall(convert_int_to_bytes(len(cert_data)))
                            client_socket.sendall(cert_data)
                            print("Server certificate begins with:\n", cert_data[:50])
                            print("[MODE 3] Authentication data sent to client.")
                            
                            
                            #SEND A AUTH MESSAGE TO AUTH CLIENT
                            server_challenge = secrets.token_bytes(32)
                            
                            #SEND M1 and M2
                            client_socket.sendall(convert_int_to_bytes(len(server_challenge)))
                            client_socket.sendall(server_challenge)
                            
                            signed_challenge_len = convert_bytes_to_int(read_bytes(client_socket,8))
                            signed_challenge = read_bytes(client_socket,signed_challenge_len)

                            client_cert_len = convert_bytes_to_int(read_bytes(client_socket,8))
                            client_cert_raw = read_bytes(client_socket,client_cert_len)
                            
                            try:
                                with open("source/auth/cacsertificate.crt","rb") as f:
                                    ca_cert_raw = f.read()
                                    ca_cert = x509.load_pem_x509_certificate(
                                        data=ca_cert_raw, backend=default_backend()
                                        )
                                    ca_public_key = ca_cert.public_key()
                                    
                                client_cert = x509.load_pem_x509_certificate(client_cert_raw, default_backend())
                                ca_public_key.verify(
                                    signature=client_cert.signature, # signature bytes to  verify
                                    data=client_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
                                    padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
                                    algorithm=client_cert.signature_hash_algorithm,
                                    )
                                
                                client_public_key = client_cert.public_key()
                                client_public_key.verify(signed_challenge,server_challenge,
                                    padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                    ),
                                    hashes.SHA256(),
                                    )
                                
                                print("[AUTH SUCCESS] Client identity verified.")

                            except InvalidSignature:
                                print("[AUTH FAILURE] Client signature verification failed. Closing connection.")
                                client_socket.close()
                                return
                            except Exception as e:
                                print("[AUTH ERROR]", e)
                                client_socket.close()
                                return               
                            


    except Exception as e:
        print(e)
        s.close()

def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    exit(0)
    
if __name__ == "__main__":
    # Tell Python to run the handler() function when SIGINT is recieved
    signal(SIGINT, handler)
    main(sys.argv[1:])
