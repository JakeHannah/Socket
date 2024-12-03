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

def server():
    ip = "127.0.0.1"
    port = 12000

    key = input("Enter a 16-character key: ")
    if len(key) != 16:
        print("Key must be 16 characters!")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(1)

    print(f"Server is listening on {ip}:{port}")

    try:
        while True:
            conn, addr = server_socket.accept()
            print(f"Connection from {addr} accepted.")

            encrypted_message = conn.recv(1024).decode()
            message = decrypt_message(encrypted_message, key)
            print(f"Decrypted message: {message}")

            response = message.upper()
            encrypted_response = encrypt_message(response, key)
            print(f"Sending encrypted response: {encrypted_response}")
            conn.send(encrypted_response.encode())

            conn.close()
            print("Client connection closed.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server_socket.close()
        print("Server shut down.")

if __name__ == "__main__":
    server()
