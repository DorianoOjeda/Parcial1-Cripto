import socket
import threading
from Crypto.Cipher import Salsa20
import os
import sys

def communication(ip_port:int):
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    SERVER = ip_address
    PORT = ip_port
    HEADER = 64
    FORMAT = 'utf-8'
    DISCONNECT_MESSAGE = "See you later, aligator"
    ADDR = (SERVER,PORT)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    clients = []  # Lista para almacenar conexiones activas de los clientes
    keys = {}  # Diccionario para almacenar las claves de los clientes

    def generate_key():
        """Genera una clave de 256 bits (32 bytes) para Salsa20."""
        return os.urandom(32)

    def encrypt_message(key, message):
        """Cifra un mensaje usando Salsa20."""
        cipher = Salsa20.new(key)
        return cipher.nonce + cipher.encrypt(message)

    def decrypt_message(key, encrypted_message):
        """Descifra un mensaje usando Salsa20."""
        nonce = encrypted_message[:8]
        ciphertext = encrypted_message[8:]
        cipher = Salsa20.new(key, nonce)
        return cipher.decrypt(ciphertext)

    def handle_client(conn, addr):
        print(f"[Nueva Conexión] {addr} se ha conectado.")
        clients.append(conn)

        # Genera y envía la clave simétrica al cliente
        key = generate_key()
        keys[conn] = key
        conn.send(key)

        connected = True
        while connected:
            try:
                msg_length = conn.recv(HEADER).decode(FORMAT)
                if msg_length:
                    msg_length = int(msg_length)
                    encrypted_msg = conn.recv(msg_length)
                    msg = decrypt_message(key, encrypted_msg).decode(FORMAT)
                    
                    if msg == DISCONNECT_MESSAGE:
                        connected = False

                    print(f"[{addr}] {msg}")
                    broadcast(msg, conn)  # Enviar el mensaje a todos los demás clientes
            except:
                break
        try:
            conn.close()
            clients.remove(conn)
            keys.pop(conn, None)  # Elimina la clave del cliente
            print(f"[Desconectado] {addr} se ha desconectado.")
        except:
            print("Error al desconectar el cliente")

    def broadcast(message, current_conn):
        """Envía un mensaje a todos los clientes conectados excepto al mismo."""
        for client in clients:
            if client != current_conn:
                try:
                    send_message(client, message)
                except:
                    client.close()
                    clients.remove(client)

    def send_message(client, message):
        """Envía un mensaje cifrado a un cliente específico."""
        key = keys[client]
        encrypted_message = encrypt_message(key, message.encode(FORMAT))
        msg_length = len(encrypted_message)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER - len(send_length))
        client.send(send_length)
        client.send(encrypted_message)

    def send_messages_from_server():
        """Función para enviar mensajes del servidor a todos los clientes."""
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

    def start():
        """Inicia el servidor y escucha nuevas conexiones de clientes."""
        server.listen()
        print(f"El servidor está funcionando en {SERVER}:{PORT}")
        
        # Crear un hilo para enviar mensajes desde el servidor
        server_message_thread = threading.Thread(target=send_messages_from_server)
        server_message_thread.start()
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
            print(f"[Conexiones activas] {threading.active_count() - 2}")

    print("[COMENZANDO] El servidor se está iniciando...")
    
    start()


if __name__ == "__main__":
    port = int(sys.argv[1])
    communication(port)