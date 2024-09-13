import socket
import threading
from Crypto.Cipher import Salsa20
import os

HEADER = 64  # Tamaño del encabezado para los mensajes
PORT = 5050  # Puerto de comunicación
SERVER = "192.168.20.29"  # Dirección IP del servidor
ADDR = (SERVER, PORT)  # Tupla con la dirección IP y el puerto
FORMAT = 'utf-8'  # Formato de codificación de los mensajes
DISCONNECT_MESSAGE = "BYE"  # Mensaje especial para desconectar

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

clients = []  # Lista para almacenar conexiones activas de los clientes
keys = {}  # Diccionario para almacenar las claves de los clientes

#Genera la llave de 256 bits (32 bytes)
def generate_key():
    return os.urandom(32)

# Cifra usando Salsa20
def encrypt_message(key, message):
    cipher = Salsa20.new(key)
    return cipher.nonce + cipher.encrypt(message)

# Descifra un mensaje usando Salsa20
def decrypt_message(key, encrypted_message):
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    cipher = Salsa20.new(key, nonce)
    return cipher.decrypt(ciphertext)

def handle_client(conn, addr):
    print(f"[Nueva Conexión] {addr} se ha conectado.")
    clients.append(conn)

    # Genera y envía la clave simétrica al cliente
    key = generate_key()
    keys[conn] = key
    conn.send(key)

    connected = True
    while connected:
        try:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg = conn.recv(msg_length)
                msg = decrypt_message(key, encrypted_msg).decode(FORMAT)

                if msg == DISCONNECT_MESSAGE:
                    connected = False

                print(f"\n[{addr}] {msg}")
                broadcast(msg, conn)  # Enviar el mensaje a todos los demás clientes
        except:
            break

    conn.close()
    clients.remove(conn)
    keys.pop(conn, None)  # Elimina la clave del cliente
    print(f"[Desconectado] {addr} se ha desconectado.")

# Envia mensajes a todos los clientes
def broadcast(message, current_conn):
    for client in clients:
        if client != current_conn: # No se lo manda a el mismo
            try:
                send_message(client, message)
            except:
                client.close()
                clients.remove(client)


# Envia los mensajes
def send_message(client, message):

    key = keys[client]
    encrypted_message = encrypt_message(key, message.encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# envia mensajes del servidor a todos los clientes
def send_messages_from_server():
    while True:
        message = input("Escribe un mensaje para los clientes: ")
        if message:
            broadcast(f"Servidor: {message}", None)
        if message == DISCONNECT_MESSAGE:
            break

    # Cierra el servidor y desconecta todos los clientes
    for client in clients:
        send_message(client, DISCONNECT_MESSAGE)
        client.close()
    server.close()


#Inicia el servidor
def start():
    server.listen()
    print(f"El servidor está funcionando en {SERVER}:{PORT}")
    
    # Crear un hilo para enviar mensajes desde el servidor
    server_message_thread = threading.Thread(target=send_messages_from_server)
    server_message_thread.start()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[Conexiones activas] {threading.active_count() - 1}")

print("[COMENZANDO] El servidor se está iniciando...")
start()