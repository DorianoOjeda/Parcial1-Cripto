import socket
import threading
from Crypto.Cipher import Salsa20
import hashlib
import random

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"
SERVER = ""  # Modificar con la dirección IP del servidor
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


p = 227  # primo
g = 12   # generador
key = None  # Clave compartida derivada

# Función para generar la clave privada y pública de Diffie-Hellman
def diffie_hellman_generate_keys(p, g):
    private_key = random.randint(1, p-1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

# Función para generar el secreto compartido
def diffie_hellman_shared_secret(their_public, my_private, p):
    return pow(their_public, my_private, p)

# Derivar una clave simétrica a partir del secreto compartido usando SHA-256
def derive_symmetric_key(shared_secret):
    shared_secret_bytes = str(shared_secret).encode('utf-8')
    symmetric_key = hashlib.sha256(shared_secret_bytes).digest()  # 32 bytes
    return symmetric_key

# Recibe la clave pública del servidor y envía la clave pública del cliente
def diffie_hellman_exchange():
    global key
    client_private_key, client_public_key = diffie_hellman_generate_keys(p, g)
    
    # Recibir la clave pública del servidor
    server_public_key = int(client.recv(HEADER).decode(FORMAT))
    
    # Enviar la clave pública del cliente al servidor
    client.send(str(client_public_key).encode(FORMAT))
    
    # Generar el secreto compartido y derivar la clave simétrica
    shared_secret = diffie_hellman_shared_secret(server_public_key, client_private_key, p)
    key = derive_symmetric_key(shared_secret)
    print(f"[INFO] Secreto compartido generado con el servidor")

# Cifra usando Salsa20
def encrypt_message(message):
    cipher = Salsa20.new(key)
    return cipher.nonce + cipher.encrypt(message)

# Descifra un mensaje usando Salsa20
def decrypt_message(encrypted_message):
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    cipher = Salsa20.new(key, nonce)
    return cipher.decrypt(ciphertext)

# Recepción de mensajes
def receive():
    while True:
        try:
            msg_length = client.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg = client.recv(msg_length)
                message = decrypt_message(encrypted_msg).decode(FORMAT)

                if message == DISCONNECT_MESSAGE:
                    print("[INFO] El servidor se ha desconectado.")
                    break

                print(f"[SERVIDOR] {message}")
        except Exception as e:
            print(f"[ERROR] {e}")
            client.close()
            break

# Enviar mensajes al servidor
def send(msg):
    encrypted_message = encrypt_message(msg.encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Inicia el cliente, realiza el intercambio de claves y comienza la recepción de mensajes
if __name__ == "__main__":
    print("[CLIENTE] Conectándose al servidor...")
    diffie_hellman_exchange()  # Realiza el intercambio de llaves Diffie-Hellman

    receive_thread = threading.Thread(target=receive)
    receive_thread.start()

    while True:
        message = input()
        send(message)
        if message == DISCONNECT_MESSAGE:
            break

    client.close()
