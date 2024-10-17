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

# Parámetros de Diffie-Hellman con q
p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903  # Número primo grande
q = 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951   # Subgrupo de orden q
g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579   # Generador

key = None  # Clave compartida derivada

# Función para generar la clave privada (en el rango [1, q-1]) y pública
def diffie_hellman_generate_keys(p, g, q):
    private_key = random.randint(1, q-1)  # Clave privada en [1, q-1]
    public_key = pow(g, private_key, p)   # Clave pública g^private_key mod p
    return private_key, public_key

# Función para generar el secreto compartido
def diffie_hellman_shared_secret(their_public, my_private, p):
    return pow(their_public, my_private, p)

# Derivar una clave simétrica a partir del secreto compartido usando SHA-256
def derive_symmetric_key(shared_secret):
    shared_secret_bytes = str(shared_secret).encode('utf-8')
    symmetric_key = hashlib.sha256(shared_secret_bytes).digest()  # 32 bytes
    return symmetric_key

# Función para enviar mensajes grandes en fragmentos
def send_large_message(socket, message):
    message = message.encode(FORMAT)  # Convertir a bytes
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    
    # Primero enviar la longitud del mensaje
    socket.send(send_length)
    
    # Luego enviar el mensaje en fragmentos de 1024 bytes
    for i in range(0, len(message), 1024):
        socket.send(message[i:i+1024])

# Función para recibir mensajes grandes en fragmentos
def receive_large_message(socket):
    msg_length = socket.recv(HEADER).decode(FORMAT)
    if msg_length:
        msg_length = int(msg_length)
        data = b""
        while len(data) < msg_length:
            packet = socket.recv(1024)
            if not packet:
                break
            data += packet
        return data.decode(FORMAT)
    return None

# Recibe la clave pública del servidor y envía la clave pública del cliente
def diffie_hellman_exchange():
    global key
    client_private_key, client_public_key = diffie_hellman_generate_keys(p, g, q)
    
    # Recibir la clave pública del servidor en fragmentos
    server_public_key = int(receive_large_message(client))
    
    # Enviar la clave pública del cliente al servidor en fragmentos
    send_large_message(client, str(client_public_key))
    
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
