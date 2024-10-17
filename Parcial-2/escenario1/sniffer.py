import socket
import struct
from math import isqrt
from Crypto.Cipher import Salsa20
import hashlib

# Variables globales
client_public_key = None
server_public_key = None
p = 137264501074495181280555132673901931323332164724815133317526595627537522562067022989603699054588480389773079016561323343477054349336451609284971148159280724829128531552270321268457769520042856144429883077983691811201653430137376919960068969990507421437958462547891425943025305810160065324145921753228735283903  # Número primo grande
q = 68632250537247590640277566336950965661666082362407566658763297813768761281033511494801849527294240194886539508280661671738527174668225804642485574079640362414564265776135160634228884760021428072214941538991845905600826715068688459980034484995253710718979231273945712971512652905080032662072960876614367641951   # Subgrupo de orden q
g = 40746562294764965373407784234554073062674073565341303353016758609344799210654104763969824808430330931109448281620048720300276969942539907157417365502013807736680793541720602226570436490901677489617911977499169334249484471027700239163555304280499401445437347279647322836086848012965178946904650279473615383579   # Generador
shared_secret = None

# Implementación del ataque de "pasos de bebé, pasos de gigante" usando q
def baby_step_giant_step(g, p, y, q):
    m = isqrt(q) + 1

    # Baby step
    print("[ATAQUE] Iniciando paso de bebé:")
    baby_steps = {}
    for j in range(m):
        baby_step_value = pow(g, j, p)
        baby_steps[baby_step_value] = j
        print(f"  [PASO BEBÉ] g^{j} [congruente] {baby_step_value} (mod {p})")

    # Giant step
    print("[ATAQUE] Iniciando paso de gigante:")
    g_inv_m = pow(g, -m, p)
    giant_step_value = y

    for i in range(m):
        print(f"  [PASO GIGANTE] Iteración {i}, g^-m^{i} * y [congruente] {giant_step_value} (mod {p})")
        if giant_step_value in baby_steps:
            x = i * m + baby_steps[giant_step_value]
            print(f"  [ÉXITO] Se encontró la clave privada: x = {x} (mod {q})")
            return x
        giant_step_value = (giant_step_value * g_inv_m) % p

    print("[ERROR] No se pudo encontrar la clave privada.")
    return None

# Derivar una clave simétrica a partir del secreto compartido usando SHA-256
def derive_symmetric_key(shared_secret):
    shared_secret_bytes = str(shared_secret).encode('utf-8')
    symmetric_key = hashlib.sha256(shared_secret_bytes).digest()  # 32 bytes
    print(f"[INFO] Clave simétrica derivada: {symmetric_key.hex()}")
    return symmetric_key

# Función para recibir mensajes en fragmentos
def receive_large_message(socket):
    HEADER = 64
    msg_length = socket.recv(HEADER).decode('utf-8').strip()
    if msg_length:
        msg_length = int(msg_length)
        data = b''
        while len(data) < msg_length:
            packet = socket.recv(1024)
            if not packet:
                break
            data += packet
        return data
    return None

# Inicia el sniffer para capturar los paquetes de la red
def start_sniffer():
    global client_public_key, server_public_key, shared_secret

    # Configura el socket para capturar paquetes en la red
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Asigna la interfaz local donde se desea capturar
    sniffer.bind(('192.168.20.29', 0))  # Cambia por la dirección IP local del sniffer

    # Coloca la tarjeta de red en modo promiscuo
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Para Windows, es necesario activar el modo promiscuo para poder capturar paquetes
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print("[SNIFFER] Iniciando captura de paquetes...")

    # Captura paquetes indefinidamente
    try:
        while True:
            # Recibe los datos del paquete
            raw_data, addr = sniffer.recvfrom(65565)

            # Obtener la cabecera IP (los primeros 20 bytes)
            ip_header = raw_data[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            # Obtener el protocolo (campo 6 de la cabecera IP)
            protocol = iph[6]
            if protocol == 6:  # Protocolo TCP
                # Extraer la cabecera TCP (20 bytes después de la cabecera IP)
                tcp_header = raw_data[20:40]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)

                # Extraer los puertos origen y destino
                src_port = tcph[0]
                dst_port = tcph[1]

                # Filtrar por puerto 5050
                if src_port == 5050 or dst_port == 5050:
                    # Extraer los datos del paquete después de la cabecera TCP
                    data_offset = (tcph[4] >> 4) * 4
                    payload = raw_data[20 + data_offset:]

                    # Verificar si el payload contiene datos
                    if payload and len(payload) > 0:
                        try:
                            # Interceptar las claves públicas del intercambio Diffie-Hellman
                            if client_public_key is None:
                                client_public_key = int.from_bytes(payload[:1024], byteorder='big')
                                print(f"[CLAVE PÚBLICA CLIENTE INTERCEPTADA]: {client_public_key}")

                            elif server_public_key is None:
                                server_public_key = int.from_bytes(payload[:1024], byteorder='big')
                                print(f"[CLAVE PÚBLICA SERVIDOR INTERCEPTADA]: {server_public_key}")

                                # Inicia el ataque de "pasos de bebé, pasos de gigante" usando q
                                attacker_private_key = baby_step_giant_step(g, p, server_public_key, q)
                                print(f"[CLAVE PRIVADA ATACANTE (CALCULADA)]: {attacker_private_key}")

                                if attacker_private_key is not None:
                                    shared_secret = pow(client_public_key, attacker_private_key, p)
                                    print(f"[SECRETO COMPARTIDO CALCULADO]: {shared_secret}")
                                    derived_key = derive_symmetric_key(shared_secret)
                                    print(f"[CLAVE SIMÉTRICA DERIVADA]: {derived_key.hex()}")

                            elif shared_secret and len(payload) > 8:
                                # Interceptar nonce de los primeros 8 bytes del mensaje cifrado
                                nonce = payload[:8]
                                encrypted_message = payload[8:]

                                print(f"[NONCE INTERCEPTADO]: {nonce.hex()}")
                                print(f"[MENSAJE CIFRADO INTERCEPTADO]: {encrypted_message.hex()}")

                                # Intentar descifrar el mensaje usando la clave derivada
                                try:
                                    cipher = Salsa20.new(key=derived_key, nonce=nonce)
                                    decrypted_message = cipher.decrypt(encrypted_message)
                                    
                                    # Verificar si es posible decodificar como UTF-8
                                    try:
                                        print(f"[MENSAJE DESCIFRADO]: {decrypted_message.decode('utf-8')}")
                                    except UnicodeDecodeError:
                                        print(f"[MENSAJE DESCIFRADO (RAW)]: {decrypted_message.hex()}")
                                except Exception as e:
                                    print(f"[ERROR DESCIFRADO]: {str(e)}")

                        except ValueError as e:
                            print(f"[ERROR] No se pudo convertir el payload a entero: {e}")

    except KeyboardInterrupt:
        print("[SNIFFER] Deteniendo captura de paquetes.")
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    start_sniffer()
