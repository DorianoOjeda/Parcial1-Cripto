import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

HEADER = 64 
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"
SERVER = "192.168.20.29" 
ADDR = (SERVER, PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

clients = []  

KEY_FILE = "aes_key.bin"  # Nombre del archivo donde se almacenará la clave AES
BLOCK_SIZE = 16  # Tamaño del bloque de AES para CBC

# Generar y almacenar la clave AES de 256 bits
def generate_and_store_key():
    key = get_random_bytes(32)  # Generar una clave de 256 bits
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print(f"[INFO] Clave AES generada y almacenada en {KEY_FILE}.")

# Leer la clave AES de 256 bits del archivo
def load_key():
    if not os.path.exists(KEY_FILE):
        generate_and_store_key()
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    return key

# Cifrar un mensaje con AES-256-CBC
def encrypt_message(key, message):
    iv = get_random_bytes(BLOCK_SIZE)  # Genera un vector de inicialización (IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = message + b' ' * (BLOCK_SIZE - len(message) % BLOCK_SIZE)  # Rellena el mensaje para que sea múltiplo del tamaño de bloque
    ciphertext = iv + cipher.encrypt(padded_message)
    return ciphertext

# Descifrar un mensaje con AES-256-CBC
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted_message[BLOCK_SIZE:]).rstrip(b' ')
    return plaintext

# Manejar la comunicación con los clientes
def handle_client(conn, addr, key):
    print(f"[Nueva Conexión] {addr} se ha conectado.")
    clients.append(conn)  # Agregar el cliente a la lista de clientes conectados

    connected = True
    while connected:
        try:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg = conn.recv(msg_length)

                # Descifra el mensaje recibido
                msg = decrypt_message(key, encrypted_msg).decode(FORMAT)

                if msg == DISCONNECT_MESSAGE:
                    connected = False

                print(f"\n[{addr}] {msg}")
                broadcast(msg, conn, key)  # Enviar el mensaje a todos los demás clientes
        except:
            break

    conn.close()
    clients.remove(conn)  # Eliminar el cliente de la lista de clientes conectados
    print(f"[Desconectado] {addr} se ha desconectado.")

# Envía un mensaje cifrado a todos los clientes conectados excepto a sí mismo
def broadcast(message, current_conn, key):
    for client in clients:
        if client != current_conn:
            try:
                send_message(client, message, key)
            except:
                client.close()
                clients.remove(client)

# Envía un mensaje cifrado a un cliente específico
def send_message(client, message, key):
    encrypted_message = encrypt_message(key, message.encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Envía mensajes del servidor a los clientes
def send_messages_from_server(key):
    while True:
        message = input("Escribe un mensaje para los clientes: ")
        if message:
            broadcast(f"Servidor: {message}", None, key)
        if message == DISCONNECT_MESSAGE:
            break

    # Cierra el servidor y desconecta todos los clientes
    for client in clients:
        send_message(client, DISCONNECT_MESSAGE, key)
        client.close()
    server.close()

# Inicia el servidor y escucha nuevas conexiones de clientes
def start():
    server.listen()
    print(f"El servidor está funcionando en {SERVER}:{PORT}")

    key = load_key()  # Carga la clave AES del archivo

    # Crear un hilo para enviar mensajes desde el servidor
    server_message_thread = threading.Thread(target=send_messages_from_server, args=(key,))
    server_message_thread.start()

    while True:
        conn, addr = server.accept()
        # Crea un nuevo hilo para manejar la conexión del cliente sin bloquear el servidor
        thread = threading.Thread(target=handle_client, args=(conn, addr, key))
        thread.start()
        print(f"[Conexiones activas] {threading.active_count() - 1}")

print("[COMENZANDO] El servidor se está iniciando...")
start()
