import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
import base64

HEADER = 64
PORT = 5050
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"
SERVER = "192.168.20.29"  # Modificar con la dirección IP del servidor
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

# Parámetros de Diffie-Hellman (Solo lo usamos para generar el secreto compartido)
p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903  # Número primo grande
q = 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951   # Subgrupo de orden q
g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579   # Generador

# Función para generar la clave privada y pública (Diffie-Hellman)
def diffie_hellman_generate_keys(p, g, q):
    private_key = random.randint(1, q-1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

# Función para generar el secreto compartido
def diffie_hellman_shared_secret(their_public, my_private, p):
    return pow(their_public, my_private, p)

# Función para el intercambio de claves Diffie-Hellman
def diffie_hellman_exchange():
    client_private_key, client_public_key = diffie_hellman_generate_keys(p, g, q)
    
    # Recibir la clave pública del servidor
    server_public_key = int(receive_large_message(client))
    
    # Enviar la clave pública del cliente
    send_large_message(client, str(client_public_key))
    
    # Generar el secreto compartido
    shared_secret = diffie_hellman_shared_secret(server_public_key, client_private_key, p)
    
    # Usar el secreto compartido para derivar una clave RSA
    return shared_secret

# Generar las claves RSA y establecer la comunicación
def rsa_exchange():
    key = RSA.generate(2048)
    private_key = key
    public_key = private_key.publickey()
    
    # Recibir la clave pública del servidor
    server_public_key_b64 = receive_large_message(client)
    server_public_key = RSA.import_key(base64.b64decode(server_public_key_b64))
    
    # Enviar la clave pública del cliente
    client_public_key_b64 = base64.b64encode(public_key.export_key(format='DER')).decode(FORMAT)
    send_large_message(client, client_public_key_b64)
    
    return private_key, server_public_key

# Cifra un mensaje usando la clave pública del servidor
def encrypt_message(message, server_public_key):
    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    return cipher_rsa.encrypt(message.encode(FORMAT))

# Descifra un mensaje usando la clave privada del cliente
def decrypt_message(encrypted_message, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_message).decode(FORMAT)

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

# Función para enviar mensajes
def send_message(message, server_public_key):
    encrypted_message = encrypt_message(message, server_public_key)
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Función para recibir mensajes
def receive_message(private_key):
    while True:
        try:
            msg_length = client.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg = client.recv(msg_length)
                message = decrypt_message(encrypted_msg, private_key)
                
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
    
    # Realizar el intercambio Diffie-Hellman
    diffie_hellman_exchange()
    
    # Realizar el intercambio de claves RSA
    private_key, server_public_key = rsa_exchange()
    
    # Iniciar el hilo para recibir mensajes
    receive_thread = threading.Thread(target=receive_message, args=(private_key,))
    receive_thread.start()

    # Enviar mensajes al servidor
    while True:
        message = input()
        send_message(message, server_public_key)
        if message == DISCONNECT_MESSAGE:
            break

    client.close()
