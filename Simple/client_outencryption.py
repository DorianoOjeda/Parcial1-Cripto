import socket
import threading
import sys

def communication(ip_port:int):

    HEADER = 64 
    PORT = ip_port
    FORMAT = 'utf-8'
    DISCONNET_MESSAGE = "BYE"
    SERVER = "" #Modificarlo con la dirección IP del servidor
    ADDR = (SERVER, PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)

    #recepcion de mensajes del servidor.
    def receive():
        while True:
            try:
                # Intenta recibir el mensaje del servidor
                msg = client.recv(HEADER).decode(FORMAT)
                if msg:
                    print(f"[Servidor] {msg}")  # Imprime el mensaje recibido
            except:
                print("[ERROR] Conexión cerrada.")
                client.close()
                break


    def send(msg):
        message = msg.encode(FORMAT)
        msg_length = len(message)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' '*(HEADER - len(send_length))
        client.send(send_length)
        client.send(message)


    # Crea un hilo para manejar la recepción de mensajes del servidor
    receive_thread = threading.Thread(target=receive)
    receive_thread.start()

    # Bucle para enviar mensajes continuamente
    while True:
        message = input() 
        send(message)  # Envía el mensaje al servidor
        if message == DISCONNET_MESSAGE:
            break  # Si el mensaje es de desconexión, sale del bucle


    client.close()  # Cierra la conexión del cliente


if __name__ == "__main__":
    port = int(sys.argv[1])
    communication(port)
