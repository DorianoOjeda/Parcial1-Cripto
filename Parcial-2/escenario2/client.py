import socket
import threading
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Math.Numbers import Integer
from Crypto.Random import get_random_bytes
import time

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"
SERVER = ""  # Dirección IP del servidor
ADDR = (SERVER, PORT)
BLOCK_SIZE = 16  # Tamaño del bloque de AES para CBC
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

# Generar clave privada y pública ECC (curva P-256)
private_key = ECC.generate(curve='P-256')
public_key = private_key.public_key()

# Enviar la clave pública serializada (en formato DER) al servidor
public_key_bytes = public_key.export_key(format='DER')
public_key_length = str(len(public_key_bytes)).encode(FORMAT)
public_key_length += b' ' * (HEADER - len(public_key_length))
client.send(public_key_length)  # Enviar la longitud primero
client.send(public_key_bytes)  # Luego enviar la clave pública

# Recibir la longitud de la clave pública del servidor
server_public_key_length = int(client.recv(HEADER).decode(FORMAT))
server_public_key_bytes = client.recv(server_public_key_length)  # Recibir la clave pública del servidor
server_public_key = ECC.import_key(server_public_key_bytes)  # Importar la clave pública del servidor

# Función para realizar manualmente el intercambio ECDH (usando la clave privada y el punto público del servidor)
def ecdh_shared_secret(private_key, server_public_key):
    server_point = server_public_key.pointQ
    shared_point = server_point * Integer(private_key.d)
    return int(shared_point.x)

# Generar el secreto compartido usando el intercambio manual
shared_secret = ecdh_shared_secret(private_key, server_public_key)

# Derivar clave AES usando HKDF
derived_key = HKDF(str(shared_secret).encode(), 32, b'', SHA256)  # Clave AES de 256 bits

# Cifrar un mensaje con AES-256-CBC
def encrypt_message(key, message):
    start_time = time.time() 
    iv = get_random_bytes(BLOCK_SIZE)  # Genera un vector de inicialización (IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = message + b' ' * (BLOCK_SIZE - len(message) % BLOCK_SIZE)  # Relleno
    ciphertext = iv + cipher.encrypt(padded_message)
    end_time = time.time()
    print(f"[INFO] Tiempo de cifrado (AES-256-CBC): {end_time - start_time} segundos")  # Mostrar tiempo de cifrado
    return ciphertext

# Descifrar un mensaje con AES-256-CBC
def decrypt_message(key, encrypted_message):
    start_time = time.time()
    iv = encrypted_message[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted_message[BLOCK_SIZE:]).rstrip(b' ')
    end_time = time.time()
    print(f"[INFO] Tiempo de descifrado (AES-256-CBC): {end_time - start_time} segundos")  # Mostrar tiempo de descifrado
    return plaintext


# Recepción de mensajes del servidor
def receive(key):
    while True:
        try:
            msg_length = client.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg = client.recv(msg_length)

                # Descifrar el mensaje recibido
                msg = decrypt_message(key, encrypted_msg).decode(FORMAT)
                print(f"[Servidor] {msg}")
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

# Iniciar hilo para manejar la recepción de mensajes
receive_thread = threading.Thread(target=receive, args=(derived_key,))
receive_thread.start()

# Bucle para enviar mensajes
while True:
    message = input()
    send(message, derived_key)
    if message == DISCONNECT_MESSAGE:
        break

client.close()
