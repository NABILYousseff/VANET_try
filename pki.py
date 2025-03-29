import socket
import threading
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64

# AES Encryption Key (must match the client's key)
AES_KEY = b'SUPER_SECURE_AES_KEY_32_BYTE!!!!'  # 32-byte AES key

# Generate ECC keys for Chameleon Hashing in LTCA


def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_key(key, private=False):
    if private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def send_request(server, port, request):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server, port))
    encrypted_request = aes_encrypt(AES_KEY, json.dumps(request))
    # Debugging
    print(
        f"Sending Encrypted Request to {server}:{port} -> {encrypted_request}")

    client.send(encrypted_request.encode())
    encrypted_response = client.recv(4096).decode()

    print(f"Received Encrypted Response: {encrypted_response}")  # Debugging
    response = json.loads(aes_decrypt(AES_KEY, encrypted_response))

    client.close()
    return response


# AES Encryption and Decryption


def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()


def aes_decrypt(key, ciphertext):
    data = base64.b64decode(ciphertext)
    iv, actual_ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(
        actual_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return (unpadder.update(padded_plaintext) + unpadder.finalize()).decode()

# Define server functions for different authorities


def start_server(role, port, handler):
    server_private_key, server_public_key = generate_ecc_keys()
    server_public_bytes = serialize_key(server_public_key)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', port))
    server.listen(5)
    print(f"{role} server listening on port {port}")
    while True:
        client, _ = server.accept()
        client.sendall(server_public_bytes.encode())
        threading.Thread(target=handler, args=(client,)).start()

# RA Handler


def ra_handler(client):
    encrypted_data = client.recv(4096).decode()
    data = json.loads(aes_decrypt(AES_KEY, encrypted_data))
    print("RA received request:", data)

    if "LTC" in data:
        # Forward LTC to LTCA for validation
        ltca_response = send_request(
            "localhost", 5001, {"Forward_To_LTCA": data["LTC"]})
        if ltca_response.get("LTC_Validation") == "Valid":
            # Request PLVs from LA1 and LA2
            la1_response = send_request(
                "localhost", 5002, {"Vehicle_ID": data["LTC"]})
            la2_response = send_request(
                "localhost", 5003, {"Vehicle_ID": data["LTC"]})

            if "PLV_LA1" in la1_response and "PLV_LA2" in la2_response:
                # Send PLVs to PCA for pseudonym certificate
                pca_response = send_request("localhost", 5004, {
                    "PLV_LA1": la1_response["PLV_LA1"],
                    "PLV_LA2": la2_response["PLV_LA2"]
                })
                client.send(aes_encrypt(
                    AES_KEY, json.dumps(pca_response)).encode())
            else:
                client.send(aes_encrypt(AES_KEY, json.dumps(
                    {"Error": "PLVs missing"})).encode())
        else:
            client.send(aes_encrypt(AES_KEY, json.dumps(
                {"Error": "Invalid LTC"})).encode())
    else:
        client.send(aes_encrypt(AES_KEY, json.dumps(
            {"Error": "LTC missing in request"})).encode())
    client.close()

# LTCA Handler (Validates LTC and provides keys to LAs)


def ltca_handler(client):
    encrypted_data = client.recv(4096).decode()
    data = json.loads(aes_decrypt(AES_KEY, encrypted_data))
    print("LTCA received LTC for validation:", data)

    if "Forward_To_LTCA" in data:
        private_key, public_key = generate_ecc_keys()
        response = aes_encrypt(AES_KEY, json.dumps({
            "LTC_Validation": "Valid",
            "Public_Key": serialize_key(public_key),
            "Private_Key": serialize_key(private_key, private=True)
        }))
    else:
        response = aes_encrypt(AES_KEY, json.dumps({"Error": "Invalid LTC"}))

    client.send(response.encode())
    client.close()

# Linkage Authority Handlers (Compute Chameleon Hash)


def la_handler(client, la_id):
    encrypted_data = client.recv(4096).decode()
    data = json.loads(aes_decrypt(AES_KEY, encrypted_data))
    print(f"{la_id} received request:", data)

    if "Vehicle_ID" in data:
        random_m = os.urandom(16).hex()
        random_r = os.urandom(16).hex()
        plv = hex(int(random_m, 16) ^ int(random_r, 16))
        response = aes_encrypt(AES_KEY, json.dumps({f"PLV_{la_id}": plv}))
    else:
        response = aes_encrypt(AES_KEY, json.dumps(
            {"Error": "Invalid Request"}))

    client.send(response.encode())
    client.close()

# PCA Handler (Compute LV and issue Pseudonym Certificate)


def pca_handler(client):
    encrypted_data = client.recv(4096).decode()
    data = json.loads(aes_decrypt(AES_KEY, encrypted_data))
    print("PCA received request:", data)

    if "PLV_LA1" in data and "PLV_LA2" in data:
        lv = hex(int(data["PLV_LA1"], 16) ^ int(data["PLV_LA2"], 16))
        response = aes_encrypt(AES_KEY, json.dumps(
            {"Pseudonym_Certificate": lv}))
    else:
        response = aes_encrypt(AES_KEY, json.dumps(
            {"Error": "Invalid Request"}))

    client.send(response.encode())
    client.close()

# Start all authority servers


def start_authorities():
    threading.Thread(target=start_server, args=(
        "RA", 5000, ra_handler)).start()
    threading.Thread(target=start_server, args=(
        "LTCA", 5001, ltca_handler)).start()
    threading.Thread(target=start_server, args=(
        "LA1", 5002, lambda c: la_handler(c, "LA1"))).start()
    threading.Thread(target=start_server, args=(
        "LA2", 5003, lambda c: la_handler(c, "LA2"))).start()
    threading.Thread(target=start_server, args=(
        "PCA", 5004, pca_handler)).start()


if __name__ == "__main__":
    start_authorities()
