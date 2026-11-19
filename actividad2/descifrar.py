#!/usr/bin/env python3
"""Laboratorio 4, Actividad 2.

Recupera el PIN cifrado con RSA-OAEP (SHA-256), deriva la clave AES-256 con
Scrypt y descifra las transacciones protegidas con AES-GCM.

Formato de los mensajes en la captura:
    RSA_PIN|<salt: 16 bytes><PIN cifrado con RSA: 256 bytes>
    AESGCM|<nonce: 12 bytes><texto cifrado><tag: 16 bytes>

Uso: python3 descifrar.py transacciones_cifradas.pcap clave_privada.pem
"""
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from scapy.all import Raw, rdpcap

ETIQUETA_PIN = b"RSA_PIN|"
ETIQUETA_AES = b"AESGCM|"
LARGO_SALT = 16     # bytes
LARGO_NONCE = 12    # bytes


def cargar_payloads(ruta_pcap):
    """Devuelve [(numero_de_paquete, datos)] de los paquetes que llevan datos."""
    return [
        (numero, bytes(paquete[Raw].load))
        for numero, paquete in enumerate(rdpcap(ruta_pcap), start=1)
        if paquete.haslayer(Raw)
    ]


def recuperar_pin(payloads, clave_privada):
    """Ubica el paquete RSA_PIN y devuelve (numero, salt, pin)."""
    for numero, datos in payloads:
        if not datos.startswith(ETIQUETA_PIN):
            continue
        resto = datos[len(ETIQUETA_PIN):]
        salt = resto[:LARGO_SALT]
        pin_cifrado = resto[LARGO_SALT:]          # 256 bytes con RSA de 2048 bits
        pin = clave_privada.decrypt(
            pin_cifrado,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return numero, salt, pin
    sys.exit("No se encontro ningun paquete con la etiqueta RSA_PIN")


def derivar_clave(pin, salt):
    """Scrypt con los parametros del enunciado: clave de 32 bytes (AES-256)."""
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pin)


def descifrar_transacciones(payloads, clave):
    """Devuelve [(numero, nonce, texto)]; texto es None si el tag no verifica."""
    aes = AESGCM(clave)
    resultado = []
    for numero, datos in payloads:
        if not datos.startswith(ETIQUETA_AES):
            continue
        resto = datos[len(ETIQUETA_AES):]
        nonce = resto[:LARGO_NONCE]
        cifrado = resto[LARGO_NONCE:]             # texto cifrado + tag de 16 bytes
        try:
            # decrypt verifica el tag antes de entregar el texto: si el mensaje
            # fue alterado o la clave no corresponde, lanza InvalidTag.
            texto = aes.decrypt(nonce, cifrado, None).decode("utf-8")
        except InvalidTag:
            texto = None
        resultado.append((numero, nonce, texto))
    return resultado


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    ruta_pcap, ruta_clave = sys.argv[1], sys.argv[2]

    with open(ruta_clave, "rb") as archivo:
        clave_privada = serialization.load_pem_private_key(archivo.read(), password=None)

    payloads = cargar_payloads(ruta_pcap)
    numero_pin, salt, pin = recuperar_pin(payloads, clave_privada)
    clave = derivar_clave(pin, salt)

    print(f"[+] Paquete RSA_PIN : #{numero_pin}")
    print(f"[+] Salt (hex)      : {salt.hex()}")
    print(f"[+] PIN recuperado  : {pin.decode()}")
    print(f"[+] Clave AES-256   : {clave.hex()}")

    transacciones = descifrar_transacciones(payloads, clave)
    autenticas = sum(1 for _, _, texto in transacciones if texto is not None)
    print(f"[+] Paquetes AESGCM : {len(transacciones)} ({autenticas} autenticados)\n")

    for numero, nonce, texto in transacciones:
        estado = texto if texto is not None else "TAG INVALIDO: mensaje alterado o clave incorrecta"
        print(f"#{numero:<3} nonce={nonce.hex()}  {estado}")


if __name__ == "__main__":
    main()
