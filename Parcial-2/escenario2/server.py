import socket
import threading
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Math.Numbers import Integer
from Crypto.Random import get_random_bytes
import os

HEADER = 64
PORT = 5050
SERVER = "192.168.20.29"
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

clients = []
shared_secrets = {}

# Generar clave privada y pública ECC (curva P256)
def generate_ecc_keys():
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()
    return private_key, public_key

# Derivar una clave simétrica a partir del secreto compartido usando HKDF
def derive_symmetric_key(shared_secret):
    derived_key = HKDF(shared_secret, 32, b'', SHA256)
    return derived_key

# Función para realizar manualmente el intercambio ECDH (usando la clave privada y el punto público del cliente)
def ecdh_shared_secret(private_key, client_public_key):
    client_point = client_public_key.pointQ
    shared_point = client_point * Integer(private_key.d)
    return int(shared_point.x)

# Cifrar un mensaje con AES-256-CBC
def encrypt_message(key, message):
    BLOCK_SIZE = 16
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = message + b' ' * (BLOCK_SIZE - len(message) % BLOCK_SIZE)
    ciphertext = iv + cipher.encrypt(padded_message)
    return ciphertext

# Descifrar un mensaje con AES-256-CBC
def decrypt_message(key, encrypted_message):
    BLOCK_SIZE = 16
    iv = encrypted_message[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted_message[BLOCK_SIZE:]).rstrip(b' ')
    return plaintext

# Manejar la comunicación con los clientes
def handle_client(conn, addr):
    print(f"[Nueva Conexión] {addr} se ha conectado.")
    clients.append(conn)

    # Intercambio de llaves Diffie-Hellman (ECC P-256)
    server_private_key, server_public_key = generate_ecc_keys()
    
    # Enviar la clave pública del servidor al cliente
    server_public_key_bytes = server_public_key.export_key(format='DER')
    server_public_key_length = str(len(server_public_key_bytes)).encode(FORMAT)
    server_public_key_length += b' ' * (HEADER - len(server_public_key_length))
    conn.send(server_public_key_length)
    conn.send(server_public_key_bytes)

    # Recibir la clave pública del cliente
    client_public_key_length = int(conn.recv(HEADER).decode(FORMAT))
    client_public_key_bytes = conn.recv(client_public_key_length)
    client_public_key = ECC.import_key(client_public_key_bytes)
    
    # Generar el secreto compartido usando el intercambio manual
    shared_secret = ecdh_shared_secret(server_private_key, client_public_key)
    symmetric_key = derive_symmetric_key(str(shared_secret).encode())
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
    shared_secrets.pop(conn, None)
    print(f"[Desconectado] {addr} se ha desconectado.")

# Envía un mensaje cifrado a todos los clientes conectados excepto al actual
def broadcast(message, current_conn):
    for client in clients:
        if client != current_conn:
            try:
                send_message(client, message)
            except:
                client.close()
                clients.remove(client)

# Envía un mensaje cifrado a un cliente específico
def send_message(client, message):
    key = shared_secrets[client]
    encrypted_message = encrypt_message(key, message.encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Envía mensajes desde el servidor a los clientes
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
