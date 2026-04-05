import base64
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pss

class Encryptor:
    def __init__(self, client_private_key_path, server_public_key_path):
        """
        Initializes the Encryptor.
        Loads the client's private key for signing,
        and the server's public key for encrypting the AES key.
        """
        # Load client private key
        with open(client_private_key_path, 'rb') as f:
            self.client_private_key = RSA.import_key(f.read())
        
        # Load server public key
        with open(server_public_key_path, 'rb') as f:
            self.server_public_key = RSA.import_key(f.read())

    def encrypt_batch(self, payload_dict):
        """
        Encrypts a dictionary payload.
        Returns the final secure payload to be sent to the server.
        """
        raw_data = json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
        
        h = SHA256.new(raw_data)
        signature = pss.new(self.client_private_key).sign(h)
        
        aes_key = get_random_bytes(32)
        nonce = get_random_bytes(12)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher_aes.encrypt_and_digest(raw_data)
        
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        return {
            "encrypted_logs": base64.b64encode(ciphertext + tag).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(nonce).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8')
        }
