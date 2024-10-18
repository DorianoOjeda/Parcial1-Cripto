import socket
import threading
from Crypto.PublicKey import ElGamal
from Crypto.Random import random
from Crypto.Hash import SHA256
import time

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"
SERVER = "192.168.20.29"  # Dirección IP del servidor
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

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
def diffie_hellman_exchange():
    client_private_key, client_public_key = diffie_hellman_generate_keys(p, g, q)

    # Recibir la clave pública del servidor
    server_public_key = int(receive_large_message(client))

    # Enviar la clave pública del cliente
    send_large_message(client, str(client_public_key))

    # Generar el secreto compartido
    shared_secret = diffie_hellman_shared_secret(server_public_key, client_private_key, p)

    print(f"[INFO] Secreto compartido generado: {shared_secret}")
    return shared_secret

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

# Función para enviar mensajes cifrados usando ElGamal
def send_message(message, shared_secret, p, g):
    c1, encrypted_message = elgamal_encrypt(message, shared_secret, p, g)

    # Enviar c1 y el mensaje cifrado
    client.send(str(c1).encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Función para recibir mensajes y descifrarlos usando ElGamal
def receive_message(shared_secret, p):
    while True:
        try:
            msg_length = client.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)

                # Recibir c1
                c1 = int(client.recv(HEADER).decode(FORMAT))

                # Recibir mensaje cifrado
                encrypted_msg = client.recv(msg_length)

                # Descifrar el mensaje
                message = elgamal_decrypt(c1, encrypted_msg, shared_secret, p)

                if message == DISCONNECT_MESSAGE:
                    print("[INFO] El servidor se ha desconectado.")
                    break

                print(f"[SERVIDOR] {message}")
        except Exception as e:
            print(f"[ERROR] {e}")
            client.close()
            break

# Inicia el cliente, realiza el intercambio de claves y comienza la recepción de mensajes
if __name__ == "__main__":
    print("[CLIENTE] Conectándose al servidor...")

    # Realiza el intercambio Diffie-Hellman
    shared_secret = diffie_hellman_exchange()

    # Iniciar el hilo para recibir mensajes
    receive_thread = threading.Thread(target=receive_message, args=(shared_secret, p))
    receive_thread.start()

    # Enviar mensajes al servidor
    while True:
        message = input()
        send_message(message, shared_secret, p, g)
        if message == DISCONNECT_MESSAGE:
            break

    client.close()
