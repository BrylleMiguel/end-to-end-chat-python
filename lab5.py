import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
import concurrent.futures
import datetime


def generate_key():
    return b"0123456789abcdef"


def generate_hmac_key():
    return b"9876543210abcdef0123456789abcdef"


def calculate_hmac(data, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    return h.digest()


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    return cipher.iv + ciphertext


def decrypt_message(encrypted_message, key):
    iv = encrypted_message[: AES.block_size]
    ciphertext = encrypted_message[AES.block_size :]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode("utf-8")


def log_message(message, hmac, timestamp):
    with open("secure_chat_log.txt", "a") as log_file:
        log_file.write(f"{timestamp} - Message: {message}, HMAC: {hmac.hex()}\n")


def log_encrypted_message(encrypted_message):
    with open("encrypted_messages.txt", "a") as encrypted_file:
        encrypted_file.write(f"{encrypted_message.hex()}\n")


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

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        server_future = executor.submit(server_message_handler, conn, key, hmac_key)
        client_future = executor.submit(client_message_handler, conn, key, hmac_key)

        concurrent.futures.wait(
            [server_future, client_future],
            return_when=concurrent.futures.FIRST_COMPLETED,
        )

    server_socket.close()


def server_message_handler(conn, key, hmac_key):
    while True:
        message = input("")
        encrypted_message = encrypt_message(message, key)
        hmac = calculate_hmac(encrypted_message, hmac_key)

        conn.sendall(encrypted_message + hmac)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message(message, hmac, timestamp)
        log_encrypted_message(encrypted_message)

        if message.lower() == "exit":
            break


def client_message_handler(conn, key, hmac_key):
    while True:
        received_data = conn.recv(1024)
        received_hmac = received_data[-32:]
        data_to_verify = received_data[:-32]

        if received_hmac == calculate_hmac(data_to_verify, hmac_key):
            decrypted_message = decrypt_message(data_to_verify, key)
            print(f"received: {decrypted_message}")

            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message(decrypted_message, received_hmac, timestamp)

            if decrypted_message.lower() == "exit":
                break
        else:
            print("HMAC verification failed. Message integrity compromised.")
            break


def start_client():
    host = input("Enter server IP address: ")
    port = 9999

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    key = generate_key()
    hmac_key = generate_hmac_key()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        receive_future = executor.submit(receive_messages, client_socket, key, hmac_key)
        send_future = executor.submit(send_messages, client_socket, key, hmac_key)

        concurrent.futures.wait(
            [receive_future, send_future],
            return_when=concurrent.futures.FIRST_COMPLETED,
        )

    client_socket.close()


def receive_messages(client_socket, key, hmac_key):
    while True:
        received_data = client_socket.recv(1024)
        received_hmac = received_data[-32:]
        data_to_verify = received_data[:-32]

        if received_hmac == calculate_hmac(data_to_verify, hmac_key):
            decrypted_message = decrypt_message(data_to_verify, key)
            print(f"received: {decrypted_message}")

            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message(decrypted_message, received_hmac, timestamp)

            if decrypted_message.lower() == "exit":
                break
        else:
            print("HMAC verification failed. Message integrity compromised.")
            break


def send_messages(client_socket, key, hmac_key):
    while True:
        message = input("")
        encrypted_message = encrypt_message(message, key)
        hmac = calculate_hmac(encrypted_message, hmac_key)
        client_socket.sendall(encrypted_message + hmac)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message(message, hmac, timestamp)
        log_encrypted_message(encrypted_message)

        if message.lower() == "exit":
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
