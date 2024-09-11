import socket
import threading
from Crypto.Cipher import Salsa20

HEADER = 64  # Tamaño del encabezado para los mensajes
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"
SERVER = "192.168.192.119"  # Dirección IP del servidor
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

key = None  # Clave de cifrado Salsa20 que se recibirá del servidor

def receive_key():
    """Recibe la clave simétrica del servidor."""
    global key
    key = client.recv(32)  # Recibe la clave de 256 bits (32 bytes)
    print(f"[INFO] Clave recibida: {key.hex()}")

def encrypt_message(message):
    """Cifra un mensaje usando Salsa20."""
    cipher = Salsa20.new(key)
    return cipher.nonce + cipher.encrypt(message)

def decrypt_message(encrypted_message):
    """Descifra un mensaje usando Salsa20."""
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    cipher = Salsa20.new(key, nonce)
    return cipher.decrypt(ciphertext)

def receive():
    """Función para manejar la recepción de mensajes desde el servidor."""
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

def send(msg):
    """Envía un mensaje cifrado al servidor."""
    encrypted_message = encrypt_message(msg.encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Inicia el cliente, recibe la clave y comienza la recepción de mensajes
if __name__ == "__main__":
    print("[CLIENTE] Conectándose al servidor...")
    receive_key()  # Recibe la clave de cifrado del servidor

    # Crea un hilo para manejar la recepción de mensajes del servidor
    receive_thread = threading.Thread(target=receive)
    receive_thread.start()

    # Bucle para enviar mensajes continuamente
    while True:
        message = input()
        send(message)  # Envía el mensaje al servidor
        if message == DISCONNECT_MESSAGE:
            break  # Si el mensaje es de desconexión, sale del bucle

    client.close()  # Cierra la conexión del cliente
