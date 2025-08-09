import base64
import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
import zipfile
from io import BytesIO
from signal import signal, SIGINT
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


def unzip_from_bytes(zip_bytes):
    extracted_files = {}
    with zipfile.ZipFile(BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            with zf.open(name) as file:
                extracted_files[name] = file.read() 
    return extracted_files


def print_progress_bar(current, total, block_num, total_blocks, bar_length=40):
    percent = current / total
    filled_length = int(bar_length * percent)
    bar = '=' * filled_length + ' ' * (bar_length - filled_length)
    sys.stdout.write(f'\rProgress: [{bar}] {percent*100:.1f}% Reading block {block_num}/{total_blocks}')
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
    private_key = None
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
                            print(_("Receiving File"))
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
                            print(_("Original File Size") + f"{original_file_size}")
                            
                            BLOCK_SIZE = 62
                            num_blocks = (original_file_size + BLOCK_SIZE-1)//BLOCK_SIZE
                            print(_("Expecting Block Size") +f"{num_blocks}")
                            decrypted_data = b''
                            encrypted_file_data = b''  # Store encrypted data for saving
                            bytes_received = 0
                            
                            for block_num in range(num_blocks):
                                
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
                                        print(_("Error Decrypting Block")+ f"{block_num}: {e}")
                                        break

                                bytes_received += BLOCK_SIZE
                                if bytes_received > original_file_size:
                                    bytes_received = original_file_size  

                                print_progress_bar(bytes_received, original_file_size, block_num + 1, num_blocks)
                            print()
                            decrypted_data = decrypted_data[:original_file_size]
                            unzipped_folder = "recv_files"

                            try:
                                with zipfile.ZipFile(BytesIO(decrypted_data)) as zip_ref:
                                    zip_ref.extractall(unzipped_folder)
                                    print(_("Successfully Unzipped Files") + f"{unzipped_folder}")
                            except zipfile.BadZipFile as e:
                                print(_("Failed to Unzip") + f"{e}")
                           
                            
                            enc_filename = "enc_"+ filename.split("/")[-1]
                            
                            with open(f"recv_files_enc/{enc_filename}", mode="wb") as fp:
                                fp.write(encrypted_file_data)
                            
                            print(_("Sucessfully Decrypted") +f"{enc_filename}")
                            print(_("Decrypted Size")+ f"{len(decrypted_data)} bytes")
                            print(_("Finished Recieving File") +f"{(time.time() - start_time)}s!")
                            

                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print(_("Closing Connection"))
                            s.close()
                            break

                        case 3:
                            print(_("Start Handshake"))

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
                            print(_("Server Certificate") + f"\n", cert_data[:50])
                            print(_("Authetication"))       
                            


    except Exception as e:
        print(e)
        s.close()

def handler(signal_received, frame):
    # Handle any cleanup here
    print(_("Exiting"))
    exit(0)
    
if __name__ == "__main__":
    # Tell Python to run the handler() function when SIGINT is recieved
    signal(SIGINT, handler)
    main(sys.argv[1:])
