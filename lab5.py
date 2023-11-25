import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
import concurrent.futures
import datetime
import os
import sys


# RSA KEY
def generate_rsa_key():
    key = RSA.generate(2048)
    return key


def save_rsa_key_to_file(key, filename):
    with open(filename, "wb") as file:
        file.write(key.export_key())


def load_rsa_key_from_file(filename):
    with open(filename, "rb") as file:
        key_data = file.read()
        key = RSA.import_key(key_data)
        return key


def encrypt_rsa_key(public_key, key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(key)
    return enc_session_key


def decrypt_rsa_key(private_key, enc_session_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    return session_key


# AES KEY
def generate_key():
    return b"0123456789abcdef"


# HMAC KEY
def generate_hmac_key():
    return b"9876543210abcdef0123456789abcdef"


# This is going to be used for comparing hmac key (this will determine if the message had been tampered)
def calculate_hmac(data, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    return h.digest()


# we add padding to fill in the last block with a fixed size
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    return cipher.iv + ciphertext


# we then remove the padding
def decrypt_message(encrypted_message, key):
    iv = encrypted_message[: AES.block_size]
    ciphertext = encrypted_message[AES.block_size :]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode("utf-8")


# logging/creating file messages
def log_integrity_and_message(message, hmac, timestamp, user):
    with open("integrity_check.txt", "a") as log_file:
        log_file.write(
            f"{timestamp} - HMAC: {hmac.hex()} - User: {user}  - Message: {message}, \n"
        )


def log_actual_messages(timestamp, message, user):
    with open("actual_messages.txt", "a") as file:
        file.write(f"{timestamp}, {user}: {message}, \n")


# logging/creating file for encrypted message
def log_encrypted_message(encrypted_message):
    with open("encrypted_messages.txt", "a") as encrypted_file:
        encrypted_file.write(f"{encrypted_message.hex()}\n")


# server
def start_server():
    host = "127.0.0.1"
    port = 9999

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print(f"Server listening on {host}:{port}")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    key = generate_key()
    hmac_key = generate_hmac_key()

    # RSA key exchange
    server_key = generate_rsa_key()
    save_rsa_key_to_file(server_key, "pri_server_key.pem")
    save_rsa_key_to_file(server_key.publickey(), "pub_server_key.pem")
    conn.sendall(server_key.publickey().export_key())

    client_key_data = conn.recv(1024)
    client_key = RSA.import_key(client_key_data)
    enc_session_key = encrypt_rsa_key(client_key, key)
    conn.sendall(enc_session_key)

    print("Previous chat:")

    with open("actual_messages.txt", "r") as logfile:
        messages = logfile.readlines()
        for message in messages:
            print(f"{message}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        server_future = executor.submit(server_send_messages, conn, key, hmac_key)
        client_future = executor.submit(server_recieve_messages, conn, key, hmac_key)

        concurrent.futures.wait(
            [server_future, client_future],
            return_when=concurrent.futures.FIRST_COMPLETED,
        )

    server_socket.close()


def server_send_messages(conn, key, hmac_key):
    while True:
        message = input("")
        encrypted_message = encrypt_message(message, key)
        hmac = calculate_hmac(encrypted_message, hmac_key)

        conn.sendall(encrypted_message + hmac)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_actual_messages(timestamp, message, "server")
        log_integrity_and_message(message, hmac, timestamp, "server sends: ")
        log_encrypted_message(encrypted_message)

        if message.lower() == "end chat":
            break


def server_recieve_messages(conn, key, hmac_key):
    while True:
        received_data = conn.recv(1024)
        received_hmac = received_data[-32:]
        data_to_verify = received_data[:-32]

        if received_hmac == calculate_hmac(data_to_verify, hmac_key):
            decrypted_message = decrypt_message(data_to_verify, key)
            print(f"client: {decrypted_message}")

            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_integrity_and_message(
                decrypted_message, received_hmac, timestamp, "server receives: "
            )

            if decrypted_message.lower() == "end chat":
                break
        else:
            print("HMAC verification failed. Message integrity compromised.")
            break


# client
def start_client():
    port = 9999

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", port))

    key = generate_key()
    hmac_key = generate_hmac_key()

    # RSA key exchange
    client_key = generate_rsa_key()
    save_rsa_key_to_file(client_key, "pri_client_key.pem")
    save_rsa_key_to_file(client_key.publickey(), "pub_client_key.pem")
    client_socket.sendall(client_key.publickey().export_key())

    server_key_data = client_socket.recv(1024)
    server_key = RSA.import_key(server_key_data)
    enc_session_key = client_socket.recv(1024)
    session_key = decrypt_rsa_key(client_key, enc_session_key)

    print("Previous chat:")

    with open("actual_messages.txt", "r") as logfile:
        messages = logfile.readlines()
        for message in messages:
            print(f"{message}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        receive_future = executor.submit(
            client_receive_messages, client_socket, session_key, hmac_key
        )
        send_future = executor.submit(
            client_send_messages, client_socket, session_key, hmac_key
        )

        concurrent.futures.wait(
            [receive_future, send_future],
            return_when=concurrent.futures.FIRST_COMPLETED,
        )

    client_socket.close()


def client_receive_messages(client_socket, key, hmac_key):
    while True:
        received_data = client_socket.recv(1024)
        received_hmac = received_data[-32:]
        data_to_verify = received_data[:-32]

        if received_hmac == calculate_hmac(data_to_verify, hmac_key):
            decrypted_message = decrypt_message(data_to_verify, key)
            print(f"server: {decrypted_message}")

            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_integrity_and_message(
                decrypted_message, received_hmac, timestamp, "client receives: "
            )

            if decrypted_message.lower() == "end chat":
                break
        else:
            print("HMAC verification failed. Message integrity compromised.")
            break


def client_send_messages(client_socket, key, hmac_key):
    while True:
        message = input("")

        if message.lower() == "delete key":
            # Simulate deleting the RSA key pairs
            os.remove("client_private_key.pem")
            os.remove("client_public_key.pem")
            print("RSA key pairs have been deleted.")

            # Notify the server that the key pairs have been deleted
            client_socket.sendall(b"KEY_DELETED")
            sys.exit("Session terminated due to deleted keys")

        encrypted_message = encrypt_message(message, key)
        hmac = calculate_hmac(encrypted_message, hmac_key)
        client_socket.sendall(encrypted_message + hmac)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_actual_messages(timestamp, message, "client")
        log_integrity_and_message(message, hmac, timestamp, "client sends: ")
        log_encrypted_message(encrypted_message)

        if message.lower() == "end chat":
            break


def main():
    print("Choose an option:")
    print("1. Start server")
    print("2. Connect to server")

    option = input("Enter option (1 or 2): ")

    if option == "1":
        start_server()
    elif option == "2":
        start_client()
    else:
        print("Invalid option. Please choose 1 or 2.")


if __name__ == "__main__":
    main()
