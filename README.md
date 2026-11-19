# Laboratorio 4: SSH y captura RSA / AES-GCM

Código del Laboratorio 4 de Criptografía y Seguridad en Redes (UDP, 2026).

## Actividad 1: servidor SSH en Docker

`actividad1/` contiene la imagen de un servidor OpenSSH restringido a cuatro algoritmos:

| Función | Algoritmo |
| --- | --- |
| Intercambio de claves | `curve25519-sha256` |
| Clave de host | `ssh-ed25519` |
| Cifrado | `aes256-ctr` |
| Integridad | `hmac-sha2-256` |

```bash
cd actividad1
docker compose up -d --build
docker exec ssh-lab4 sshd -T | grep -Ei '^(kexalgorithms|ciphers|macs|hostkeyalgorithms|hostkey) '
ssh -vv -p 2222 lab4@127.0.0.1      # contraseña: lab4pass
```

La captura de la conexión está en `capturas/ssh-lab4.pcapng` (interfaz `lo`, filtro `tcp.port == 2222`) y la depuración del cliente en `capturas/ssh-vv.log`.

## Actividad 2: descifrado de la captura antigua

`actividad2/descifrar.py` lee la captura, recupera el PIN cifrado con RSA-OAEP (SHA-256), deriva la clave AES-256 con Scrypt (`n=2**14`, `r=8`, `p=1`) y descifra y autentica las 40 transacciones AES-GCM.

La captura `transacciones_cifradas.pcap` y la clave `clave_privada.pem` no están en el repositorio. Se descargan desde la carpeta [Captura y Claves](https://drive.google.com/drive/folders/1rXMp5y9WeBR36iytc4RBaqXKWf3ea-WU) del curso y se dejan en `actividad2/`.

```bash
cd actividad2
python3 -m venv venv && source venv/bin/activate
pip install cryptography scapy
python3 descifrar.py transacciones_cifradas.pcap clave_privada.pem
```

La salida esperada está en `capturas/salida-descifrar.txt`: PIN `4827` y 40 transacciones autenticadas.
