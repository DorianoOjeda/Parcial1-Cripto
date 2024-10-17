import socket
import threading
import random
from Crypto.Cipher import Salsa20
import hashlib

HEADER = 64  # Tamaño del encabezado para los mensajes
PORT = 5050
SERVER = "192.168.20.29"  # Modificar con la IP del servidor
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "BYE"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

clients = []  # Lista para almacenar conexiones activas de los clientes
shared_secrets = {}  # Diccionario para almacenar los secretos compartidos de cada cliente

# Parámetros para Diffie-Hellman con q
p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903  # Número primo grande
q = 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951   # Subgrupo de orden q
g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579   # Generador

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

# Manejador de clientes
def handle_client(conn, addr):
    print(f"[Nueva Conexión] {addr} se ha conectado.")
    clients.append(conn)

    # Intercambio de llaves Diffie-Hellman
    server_private_key, server_public_key = diffie_hellman_generate_keys(p, g, q)
    
    # Enviar la clave pública del servidor al cliente en fragmentos
    send_large_message(conn, str(server_public_key))
    
    # Recibir la clave pública del cliente en fragmentos
    client_public_key = int(receive_large_message(conn))
    
    # Generar el secreto compartido
    shared_secret = diffie_hellman_shared_secret(client_public_key, server_private_key, p)
    symmetric_key = derive_symmetric_key(shared_secret)
    shared_secrets[conn] = symmetric_key
    
    print(f"[INFO] Secreto compartido generado con {addr}")

    connected = True
    while connected:
        try:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg = conn.recv(msg_length)
                msg = decrypt_message(symmetric_key, encrypted_msg).decode(FORMAT)

                if msg == DISCONNECT_MESSAGE:
                    connected = False

                print(f"\n[{addr}] {msg}")
                broadcast(msg, conn)
        except:
            break

    conn.close()
    clients.remove(conn)
    shared_secrets.pop(conn, None)  # Eliminar el secreto del cliente
    print(f"[Desconectado] {addr} se ha desconectado.")

# Cifra usando Salsa20
def encrypt_message(key, message):
    cipher = Salsa20.new(key=key)
    return cipher.nonce + cipher.encrypt(message)

# Descifra usando Salsa20
def decrypt_message(key, encrypted_message):
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)

# Envia mensajes a todos los clientes
def broadcast(message, current_conn):
    for client in clients:
        if client != current_conn:
            try:
                send_message(client, message)
            except:
                client.close()
                clients.remove(client)

# Envia los mensajes cifrados
def send_message(client, message):
    key = shared_secrets[client]
    encrypted_message = encrypt_message(key, message.encode(FORMAT))
    msg_length = len(encrypted_message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)

# Envia mensajes del servidor a los clientes
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
