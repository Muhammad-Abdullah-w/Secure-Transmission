import sslcrypto
import pickle
import socket
import base64, io, gzip


def generate_keys():
    curve = sslcrypto.ecc.get_curve("secp192k1")
    
    #  private key
    ecc_private_key = curve.new_private_key(is_compressed=True)

    #  public key
    ecc_public_key = curve.private_to_public(ecc_private_key)

    return ecc_public_key, ecc_private_key


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
        
def decode_string(encoded_text):
    """Decode the given base64 encoded text."""
    return base64.b64decode(encoded_text)

def decompress_bytes(compressed_bytes):
    """Decompress the given gzip compressed bytes."""
    return gzip.decompress(compressed_bytes)

def decrypt(ciphertext, key):
    curve = sslcrypto.ecc.get_curve("secp192k1")
    plaintext = curve.decrypt(ciphertext, key, algo="aes-256-ofb")
    return plaintext


if __name__ == "__main__":

    ecc_public_key, ecc_private_key = generate_keys()  #==========> Step 1 generating public and private key
    port = 9998
    sender(ecc_public_key, 'localhost', port)  #===========> Step 2 sending public key


    cipher_text=receiver('localhost', 9997)   # Cipher Text Received in Screen 1

    print("Received Cipher ",cipher_text)

    #===========> Step 5 De-Cipher process

    decoded_bytes = decode_string(cipher_text)                 #decoding
    decrypted_message = decrypt(decoded_bytes, ecc_private_key)     #decryption
    decompressed_text = decompress_bytes(decrypted_message)              #decompression
    
    print("\n\n Received Message: ", decompressed_text)
