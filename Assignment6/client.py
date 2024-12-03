import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_message(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv=b'1234567890123456')
    encrypted = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(encrypted_message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv=b'1234567890123456')
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_message)), AES.block_size)
    return decrypted.decode('utf-8')

def client():
    ip = "127.0.0.1"
    port = 12000

    # Ask the user for a key
    key = input("Enter a 16-character key: ")
    if len(key) != 16:
        print("Key must be 16 characters!")
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((ip, port))
        print(f"Connected to server at {ip}:{port}")

        message = input("Enter your message: ")
        encrypted_message = encrypt_message(message, key)
        print(f"Sending encrypted message: {encrypted_message}")
        client_socket.send(encrypted_message.encode())

        response = client_socket.recv(1024).decode()
        decrypted_response = decrypt_message(response, key)
        print(f"Decrypted response: {decrypted_response}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    client()
