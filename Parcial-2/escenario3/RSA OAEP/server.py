import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
import base64
import time

HEADER = 64
PORT = 5050
SERVER = "192.168.20.29"  # Dirección IP del servidor
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

clients = []
shared_public_keys = {}

# Parámetros Diffie-Hellman (Solo lo usamos para generar el secreto compartido)
p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903
q = 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951
g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579

# Función para generar la clave privada y pública (Diffie-Hellman)
def diffie_hellman_generate_keys(p, g, q):
    private_key = random.randint(1, q-1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

# Función para generar el secreto compartido
def diffie_hellman_shared_secret(their_public, my_private, p):
    return pow(their_public, my_private, p)

# Función para el intercambio de claves Diffie-Hellman
def diffie_hellman_exchange(conn):
    server_private_key, server_public_key = diffie_hellman_generate_keys(p, g, q)
    
    # Enviar la clave pública del servidor
    send_large_message(conn, str(server_public_key))
    
    # Recibir la clave pública del cliente
    client_public_key = int(receive_large_message(conn))
    
    # Generar el secreto compartido
    shared_secret = diffie_hellman_shared_secret(client_public_key, server_private_key, p)
    
    return shared_secret

# Generar claves RSA
def rsa_exchange(conn):
    key = RSA.generate(2048)
    private_key = key
    public_key = private_key.publickey()
    
    # Enviar la clave pública al cliente
    public_key_b64 = base64.b64encode(public_key.export_key(format='DER')).decode(FORMAT)
    send_large_message(conn, public_key_b64)
    
    # Recibir la clave pública del cliente
    client_public_key_b64 = receive_large_message(conn)
    client_public_key = RSA.import_key(base64.b64decode(client_public_key_b64))
    
    shared_public_keys[conn] = client_public_key
    return private_key

# Cifrar el mensaje usando la clave pública del cliente
def encrypt_message(message, client_public_key):
    start_time = time.time()
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode(FORMAT))
    end_time = time.time()
    print(f"[INFO] Tiempo de cifrado (RSA-OAEP): {end_time - start_time} segundos")  # Mostrar tiempo de cifrado
    return encrypted_message

# Descifrar el mensaje usando la clave privada del servidor
def decrypt_message(encrypted_message, private_key):
    start_time = time.time()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    message = cipher_rsa.decrypt(encrypted_message).decode(FORMAT)
    end_time = time.time()
    print(f"[INFO] Tiempo de descifrado (RSA-OAEP): {end_time - start_time} segundos")  # Mostrar tiempo de descifrado
    return message


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

# Función para manejar clientes
def handle_client(conn, addr):
    print(f"[Nueva Conexión] {addr} se ha conectado.")
    clients.append(conn)

    # Intercambio de claves Diffie-Hellman
    diffie_hellman_exchange(conn)
    
    # Intercambio de claves RSA
    private_key = rsa_exchange(conn)

    connected = True
    while connected:
        try:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg = conn.recv(msg_length)

                # Descifrar el mensaje
                message = decrypt_message(encrypted_msg, private_key)

                if message == DISCONNECT_MESSAGE:
                    connected = False

                print(f"[{addr}] {message}")
                broadcast(message, conn)
        except:
            break

    conn.close()
    clients.remove(conn)
    shared_public_keys.pop(conn, None)
    print(f"[Desconectado] {addr} se ha desconectado.")

# Función para enviar mensajes cifrados
def broadcast(message, current_conn):
    for client in clients:
        if client != current_conn:
            send_message(client, message)

# Enviar mensajes cifrados a los clientes
def send_message(client, message):
    client_public_key = shared_public_keys[client]
    encrypted_message = encrypt_message(message, client_public_key)
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Enviar mensajes desde el servidor a todos los clientes
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
