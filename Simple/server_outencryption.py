import socket 
import threading
import sys

def communication(ip_port):

    HEADER = 64  
    PORT =   ip_port
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    SERVER = ip_address
    ADDR = (SERVER, PORT) 
    FORMAT = 'utf-8' 
    DISCONNECT_MESSAGE = "See you later, aligator" 

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)

    # Lista para almacenar conexiones activas de los clientes
    clients = []

    #Maneja la comunicacion los clientes.
    def handle_client(conn, addr):
        print(f"[Nueva Conexión] {addr} se ha conectado.")
        clients.append(conn)  # Agregar el cliente a la lista de clientes conectados

        connected = True
        while connected:
            try:
                msg_length = conn.recv(HEADER).decode(FORMAT)
                if msg_length:
                    msg_length = int(msg_length)
                    msg = conn.recv(msg_length).decode(FORMAT)

                    if msg == DISCONNECT_MESSAGE:
                        connected = False

                    print(f"[{addr}] {msg}")
                    broadcast(msg, conn)  # Enviar el mensaje a todos los demás clientes
            except:
                break

        conn.close()
        clients.remove(conn)  # Eliminar el cliente de la lista de clientes conectados
        print(f"[Desconectado] {addr} se ha desconectado.")


    #Envía un mensaje a todos los clientes conectados excepto a el mismo.
    def broadcast(message, current_conn):
        for client in clients:
            if client != current_conn:
                try:
                    send_message(client, message)
                except:
                    client.close()
                    clients.remove(client)

    def send_message(client, message):
        message = message.encode(FORMAT)
        msg_length = len(message)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER - len(send_length))
        client.send(send_length)
        client.send(message)

    def send_messages_from_server():
        while True:
            message = input("Escribe un mensaje para los clientes: ")
            if message:
                broadcast(f"Servidor: {message}", None)
            if message == DISCONNECT_MESSAGE:
                break

        # Cierra el servidor y desconecta todos los clientes
        for client in clients:
            send_message(client, DISCONNECT_MESSAGE)
            client.close()
        server.close()


    #Inicia el servidor y escucha nuevas conexiones de clientes.
    def start():
        server.listen()
        print(f"El servidor está funcionando en {SERVER}:{PORT}")
        
        # Crear un hilo para enviar mensajes desde el servidor
        server_message_thread = threading.Thread(target=send_messages_from_server)
        server_message_thread.start()

        while True:
            conn, addr = server.accept()
            # Crea un nuevo hilo para manejar la conexión del cliente sin bloquear el servidor
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
            print(f"[Conexiones activas] {threading.active_count() - 1}")

    print("[COMENZANDO] El servidor se está iniciando...")

    start()


if __name__ == "__main__":
    port = int(sys.argv[1])
    communication(port)
