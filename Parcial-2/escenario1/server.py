import socket
import threading
import os
import random
from Crypto.Cipher import Salsa20
import hashlib

HEADER = 64  # Tamaño del encabezado para los mensajes
PORT = 5050
SERVER = "192.168.20.29"
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

clients = []  # Lista para almacenar conexiones activas de los clientes
shared_secrets = {}  # Diccionario para almacenar los secretos compartidos de cada cliente

# Parámetros para Diffie-Hellman
p = 227  # primo
g = 12   # generador

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

# Cifra usando Salsa20
def encrypt_message(key, message):
    cipher = Salsa20.new(key=key)
    return cipher.nonce + cipher.encrypt(message)

# Descifra usando Salsa20
def decrypt_message(key, encrypted_message):
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)

# Manejador de clientes
def handle_client(conn, addr):
    print(f"[Nueva Conexión] {addr} se ha conectado.")
    clients.append(conn)

    # Intercambio de llaves Diffie-Hellman
    server_private_key, server_public_key = diffie_hellman_generate_keys(p, g)
    
    # Enviar la clave pública al cliente
    conn.send(str(server_public_key).encode(FORMAT))
    
    # Recibir la clave pública del cliente
    client_public_key = int(conn.recv(HEADER).decode(FORMAT))
    
    # Generar el secreto compartido
    shared_secret = diffie_hellman_shared_secret(client_public_key, server_private_key, p)
    symmetric_key = derive_symmetric_key(shared_secret)
    shared_secrets[conn] = symmetric_key
    
    print(f"[INFO] Secreto compartido generado con {addr}")

    connected = True
    while connected:
        try:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg = conn.recv(msg_length)
                msg = decrypt_message(symmetric_key, encrypted_msg).decode(FORMAT)

                if msg == DISCONNECT_MESSAGE:
                    connected = False

                print(f"\n[{addr}] {msg}")
                broadcast(msg, conn)
        except:
            break

    conn.close()
    clients.remove(conn)
    shared_secrets.pop(conn, None)  # Eliminar el secreto del cliente
    print(f"[Desconectado] {addr} se ha desconectado.")

# Envia mensajes a todos los clientes
def broadcast(message, current_conn):
    for client in clients:
        if client != current_conn:
            try:
                send_message(client, message)
            except:
                client.close()
                clients.remove(client)

# Envia los mensajes cifrados
def send_message(client, message):
    key = shared_secrets[client]
    encrypted_message = encrypt_message(key, message.encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Envia mensajes del servidor a los clientes
def send_messages_from_server():
    while True:
        message = input("Escribe un mensaje para los clientes: ")
        if message:
            broadcast(f"Servidor: {message}", None)
        if message == DISCONNECT_MESSAGE:
            break

    for client in clients:
        send_message(client, DISCONNECT_MESSAGE)
        client.close()
    server.close()

# Iniciar el servidor
def start():
    server.listen()
    print(f"El servidor está funcionando en {SERVER}:{PORT}")
    
    server_message_thread = threading.Thread(target=send_messages_from_server)
    server_message_thread.start()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[Conexiones activas] {threading.active_count() - 1}")

print("[COMENZANDO] El servidor se está iniciando...")
start()
