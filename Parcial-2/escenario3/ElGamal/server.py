import socket
import threading
from Crypto.PublicKey import ElGamal
from Crypto.Random import random
from Crypto.Hash import SHA256
import time  # Agregar esta línea para medir el tiempo

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
public_keys = {}

p = 14330819  # Número primo grande
q = 7165409  # Subgrupo de orden q
g = 1970788   # Generador

# Generar claves Diffie-Hellman (privada y pública)
def diffie_hellman_generate_keys(p, g, q):
    private_key = random.randint(1, q-1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

# Función para generar el secreto compartido usando Diffie-Hellman
def diffie_hellman_shared_secret(their_public, my_private, p):
    return pow(their_public, my_private, p)

# Cifra un mensaje usando ElGamal con una clave derivada del secreto compartido
def elgamal_encrypt(message, shared_secret, p, g):
    start_time = time.time()
    k = random.randint(1, p-2)  # Número aleatorio para cada mensaje
    c1 = pow(g, k, p)
    hashed_secret = SHA256.new(str(shared_secret).encode(FORMAT)).digest()
    encrypted_message = bytes([_a ^ _b for _a, _b in zip(message.encode(FORMAT), hashed_secret)])
    end_time = time.time()
    print(f"[INFO] Tiempo de cifrado (ElGamal): {end_time - start_time} segundos")  # Mostrar tiempo de cifrado
    return (c1, encrypted_message)

# Descifra un mensaje usando ElGamal
def elgamal_decrypt(c1, encrypted_message, shared_secret, p):
    start_time = time.time()
    hashed_secret = SHA256.new(str(shared_secret).encode(FORMAT)).digest()
    decrypted_message = bytes([_a ^ _b for _a, _b in zip(encrypted_message, hashed_secret)])
    end_time = time.time()
    print(f"[INFO] Tiempo de descifrado (ElGamal): {end_time - start_time} segundos")  # Mostrar tiempo de descifrado
    return decrypted_message.decode(FORMAT)


# Intercambio de claves Diffie-Hellman
def diffie_hellman_exchange(conn):
    server_private_key, server_public_key = diffie_hellman_generate_keys(p, g, q)

    # Enviar la clave pública del servidor al cliente
    send_large_message(conn, str(server_public_key))

    # Recibir la clave pública del cliente
    client_public_key = int(receive_large_message(conn))

    # Generar el secreto compartido
    shared_secret = diffie_hellman_shared_secret(client_public_key, server_private_key, p)

    # Guardar la clave pública del cliente y el secreto compartido
    public_keys[conn] = client_public_key
    shared_secrets[conn] = shared_secret

    print(f"[INFO] Secreto compartido generado con el cliente: {shared_secret}")
    return server_private_key, client_public_key

# Funciones para manejar mensajes grandes
def send_large_message(socket, message):
    message = message.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    socket.send(send_length)
    socket.send(message)

def receive_large_message(socket):
    msg_length = socket.recv(HEADER).decode(FORMAT)
    if msg_length:
        msg_length = int(msg_length)
        data = socket.recv(msg_length)
        return data.decode(FORMAT)
    return None

# Función para manejar los clientes
def handle_client(conn, addr):
    print(f"[Nueva Conexión] {addr} se ha conectado.")
    clients.append(conn)

    # Intercambio de claves Diffie-Hellman
    server_private_key, client_public_key = diffie_hellman_exchange(conn)

    connected = True
    while connected:
        try:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)

                # Recibir c1
                c1 = int(conn.recv(HEADER).decode(FORMAT))

                # Recibir el mensaje cifrado
                encrypted_msg = conn.recv(msg_length)

                # Obtener el secreto compartido
                shared_secret = shared_secrets[conn]

                # Descifrar el mensaje
                message = elgamal_decrypt(c1, encrypted_msg, shared_secret, p)

                if message == DISCONNECT_MESSAGE:
                    connected = False

                print(f"[{addr}] {message}")
                broadcast(message, conn)
        except Exception as e:
            print(f"[ERROR] {e}")
            break

    conn.close()
    clients.remove(conn)
    shared_secrets.pop(conn, None)
    public_keys.pop(conn, None)
    print(f"[Desconectado] {addr} se ha desconectado.")

# Función para enviar mensajes cifrados a los clientes
def broadcast(message, current_conn):
    for client in clients:
        if client != current_conn:
            send_message(client, message)

# Función para cifrar y enviar mensajes
def send_message(client, message):
    # Obtener la clave pública del cliente y el secreto compartido
    shared_secret = shared_secrets[client]
    c1, encrypted_message = elgamal_encrypt(message, shared_secret, p, g)

    # Enviar c1 y el mensaje cifrado
    client.send(str(c1).encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Función para enviar mensajes desde el servidor
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
