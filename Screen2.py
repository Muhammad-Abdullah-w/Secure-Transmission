import sslcrypto
import pickle
import socket
import base64, io, gzip
import hashlib

def receiver(host, port):
    # Create a socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            data = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk

            # Deserialize the data
            received_data = pickle.loads(data)
            packet = received_data['packet']
            
            return packet


def sender(ecc_public_key, host, port):
    # Combine the data into a dictionary
    data = {
        'packet': ecc_public_key,
    }
    
    # Serialize the data
    serialized_data = pickle.dumps(data)

    # Create a socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(serialized_data)
        

def encode_string(text):
    """Encode the given text using base64."""
    return base64.b64encode(text)


def compress_bytes(string_obj):
    """Compress the given string using gzip."""
    with io.BytesIO() as buf:
        with gzip.GzipFile(fileobj=buf, mode='wb') as f:
            f.write(string_obj.encode())
        return buf.getvalue()


def encrypt(data_ecc,ecc_public_key):
    curve = sslcrypto.ecc.get_curve("secp192k1")
    # Encrypt something
    ciphertext = curve.encrypt(data_ecc, ecc_public_key, algo="aes-256-ofb")
    return ciphertext


if __name__ == "__main__":
    
    ecc_public_key = receiver('localhost', 9998) #  Public Key Received in Screen 2 
    print(ecc_public_key)
    
    
    message = str(input("Enter message"))
    
    # =========================>  Step 3 Making of Cipher <======================= #

    compressed_data = compress_bytes(message)            # compression
    ciphertext = encrypt(compressed_data, ecc_public_key)   #  encryption
    encoded_text = encode_string(ciphertext)             # encoding
    

    # =========================>  Step 4 Sending Cipher <======================= #
        
    sender(encoded_text, 'localhost', 9997)              

