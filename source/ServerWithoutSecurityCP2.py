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

                            decrypted_data = b''
                            encrypted_file_data = b''

                            total_received = 0
                            while total_received < original_file_size:
                                # Read block length (M2 format changed in CP2)
                                block_len = convert_bytes_to_int(read_bytes(client_socket, 8))

                                # Read the actual encrypted block
                                encrypted_block = read_bytes(client_socket, block_len)
                                encrypted_file_data += encrypted_block
                                try:
                                    decrypted_block = fernet.decrypt(encrypted_block)
                                    decrypted_data += decrypted_block
                                    total_received += len(decrypted_block)
                                except Exception as e:
                                    print(f"Error decrypting block: {e}")
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
                            nonce_message = read_bytes(client_socket,msg_len)
                            

                            #LOADING PRIVATE KEY
                            with open("source/auth/server_private_key.pem", mode="rb") as key_file:
                                private_key = serialization.load_pem_private_key(bytes(key_file.read()), password=None)
                                
                            #SIGN MESSAGE WITH PSS 
                            signature = private_key.sign(
                                nonce_message,
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

                        case 4:
                            print("[MODE 4] Receiving encrypted session key...")

                            encrypted_len = convert_bytes_to_int(read_bytes(client_socket, 8))
                            encrypted_session_key = read_bytes(client_socket, encrypted_len)

                            # Decrypt Fernet session key
                            session_key = private_key.decrypt(
                                encrypted_session_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                )
                            )
                            fernet = Fernet(session_key)
                            print("[MODE 4] Session key received and decrypted.")
                            


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
