import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

HEADER = 64 
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"
SERVER = "" #Modificarlo con la dirección IP del servidor
ADDR = (SERVER, PORT)
KEY_FILE = "aes_key.bin"  # Nombre del archivo que contiene la clave AES
BLOCK_SIZE = 16  # Tamaño del bloque de AES para CBC

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

# Leer la clave AES de 256 bits del archivo
def load_key():
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError(f"[ERROR] No se encontró el archivo de clave AES: {KEY_FILE}")
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

# Recepción de mensajes del servidor
def receive(key):
    while True:
        try:
            # Intenta recibir el mensaje del servidor
            msg_length = client.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg = client.recv(msg_length)

                # Descifra el mensaje recibido
                msg = decrypt_message(key, encrypted_msg).decode(FORMAT)
                print(f"[Servidor] {msg}")  # Imprime el mensaje recibido
        except:
            print("[ERROR] Conexión cerrada.")
            client.close()
            break

# Enviar mensajes al servidor
def send(msg, key):
    encrypted_message = encrypt_message(key, msg.encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Código principal del cliente
# Cargar la clave AES desde el archivo
key = load_key()

# Crea un hilo para manejar la recepción de mensajes del servidor
receive_thread = threading.Thread(target=receive, args=(key,))
receive_thread.start()

# Bucle para enviar mensajes continuamente
while True:
    message = input() 
    send(message, key)  # Envía el mensaje cifrado al servidor
    if message == DISCONNECT_MESSAGE:
        break  # Si el mensaje es de desconexión, sale del bucle

client.close()  # Cierra la conexión del cliente
