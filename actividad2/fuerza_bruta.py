#!/usr/bin/env python3
"""Recupera el PIN sin la clave privada: prueba los 10.000 PIN posibles con
Scrypt y usa el tag de AES-GCM para reconocer el correcto.

Uso: python3 fuerza_bruta.py transacciones_cifradas.pcap
"""
import sys
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from scapy.all import Raw, rdpcap

payloads = [bytes(p[Raw].load) for p in rdpcap(sys.argv[1]) if p.haslayer(Raw)]
salt = next(d for d in payloads if d.startswith(b"RSA_PIN|"))[8:24]
mensaje = next(d for d in payloads if d.startswith(b"AESGCM|"))[7:]
nonce, cifrado = mensaje[:12], mensaje[12:]

inicio = time.time()
for numero in range(10_000):
    pin = f"{numero:04d}".encode()
    clave = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pin)
    try:
        texto = AESGCM(clave).decrypt(nonce, cifrado, None)
    except InvalidTag:
        continue
    print(f"PIN encontrado: {pin.decode()} tras {numero + 1} intentos y {time.time() - inicio:.0f} s")
    print(texto.decode())
    break
