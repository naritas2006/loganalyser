import sys
import os
import pytest
import json
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keys.generate_keys import generate_key_pair
from client.encryptor import Encryptor
from server.decryptor import Decryptor

@pytest.fixture(scope="module")
def setup_keys():
    os.makedirs("keys", exist_ok=True)
    generate_key_pair("keys", "test_client")
    generate_key_pair("keys", "test_server")
    yield

    for f in ["test_client_private.pem", "test_client_public.pem", "test_server_private.pem", "test_server_public.pem"]:
        try:
            os.remove(os.path.join("keys", f))
        except OSError:
            pass

def test_full_encryption_cycle(setup_keys):
    client = Encryptor("keys/test_client_private.pem", "keys/test_server_public.pem")
    server = Decryptor("keys/test_server_private.pem", "keys/test_client_public.pem")
    
    original_payload = {
        "device_id": "test_device_1",
        "timestamp": "2026-03-30T12:00:00Z",
        "kid": "client_v1",
        "sequence_number": 1,
        "logs": [
            {"raw_logs": "test log message 1", "log_source": "syslog"},
            {"raw_logs": "test log message 2", "log_source": "auth"}
        ]
    }
    
    encrypted_dict = client.encrypt_batch(original_payload)
    
    assert "encrypted_logs" in encrypted_dict
    assert "encrypted_aes_key" in encrypted_dict
    assert "signature" in encrypted_dict
    assert "iv" in encrypted_dict
    
    decrypted_payload, events = server.decrypt_and_verify(encrypted_dict)
    
    assert decrypted_payload["device_id"] == original_payload["device_id"]
    assert decrypted_payload["logs"] == original_payload["logs"]
    assert any(e["event_type"] == "AES Payload Decryption" and e["status"] == "Success" for e in events)
    assert any(e["event_type"] == "Signature Verification" and e["status"] == "Success" for e in events)

def test_signature_tampering(setup_keys):
    client = Encryptor("keys/test_client_private.pem", "keys/test_server_public.pem")
    server = Decryptor("keys/test_server_private.pem", "keys/test_client_public.pem")
    
    original_payload = {"test": "tamper me"}
    encrypted_dict = client.encrypt_batch(original_payload)

    sig_bytes = bytearray(base64.b64decode(encrypted_dict["signature"]))
    if sig_bytes:
        sig_bytes[0] ^= 0x01
    encrypted_dict["signature"] = base64.b64encode(bytes(sig_bytes)).decode("utf-8")

    decrypted_payload, events = server.decrypt_and_verify(encrypted_dict)
    assert decrypted_payload is None
    assert any(e["event_type"] == "Signature Verification" and e["status"] == "Failure" for e in events)


def test_ciphertext_tampering_detected_by_gcm(setup_keys):
    client = Encryptor("keys/test_client_private.pem", "keys/test_server_public.pem")
    server = Decryptor("keys/test_server_private.pem", "keys/test_client_public.pem")

    original_payload = {"msg": "gcm tamper test"}
    encrypted_dict = client.encrypt_batch(original_payload)

    corrupted = bytearray(base64.b64decode(encrypted_dict["encrypted_logs"]))
    if corrupted:
        corrupted[0] ^= 0x01
    encrypted_dict["encrypted_logs"] = base64.b64encode(bytes(corrupted)).decode("utf-8")

    decrypted_payload, events = server.decrypt_and_verify(encrypted_dict)
    assert decrypted_payload is None
    assert any(e["event_type"] == "AES Payload Decryption" and e["status"] == "Failure" for e in events)
