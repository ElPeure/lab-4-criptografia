#!/usr/bin/env python3
"""Laboratorio 4 - Actividad 2: recuperación del PIN (RSA-OAEP) y descifrado AES-GCM."""
import struct, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PCAP = sys.argv[1] if len(sys.argv) > 1 else "transacciones_cifradas.pcap"
PRIV = sys.argv[2] if len(sys.argv) > 2 else "clave_privada.pem"


def leer_pcap(ruta):
    """Devuelve el payload TCP de cada paquete (captura Raw IPv4, linktype 101)."""
    datos = open(ruta, "rb").read()
    off, n = 24, 0
    while off < len(datos):
        _, _, caplen, _ = struct.unpack("<IIII", datos[off:off + 16])
        off += 16
        pkt = datos[off:off + caplen]
        off += caplen
        n += 1
        ihl = (pkt[0] & 0x0F) * 4
        if pkt[9] != 6:                      # solo TCP
            continue
        thl = ((pkt[ihl + 12] >> 4) & 0x0F) * 4
        yield n, pkt[ihl + thl:]


def main():
    paquetes = [(n, p) for n, p in leer_pcap(PCAP) if p]

    # 1) Paquete RSA_PIN: etiqueta | salt(16) | PIN cifrado con RSA
    n_pin, p = next((n, p) for n, p in paquetes if p.startswith(b"RSA_PIN|"))
    cuerpo = p[len(b"RSA_PIN|"):]
    salt, pin_cifrado = cuerpo[:16], cuerpo[16:]
    print(f"[i] Paquete RSA_PIN: #{n_pin} | salt={salt.hex()} | PIN cifrado={len(pin_cifrado)} bytes")

    # 2) Descifrado RSA-OAEP (SHA-256)
    with open(PRIV, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    pin = priv.decrypt(
        pin_cifrado,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    print("[+] PIN recuperado mediante RSA")
    print(f"[+] PIN: {pin.decode()}")

    # 3) Derivación de la clave AES-256 con Scrypt (n=2^14, r=8, p=1)
    clave = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pin)
    print(f"[i] Clave AES-256 derivada: {clave.hex()}")

    # 4) Paquetes AESGCM: etiqueta | nonce(12) | ciphertext+tag(16)
    aes = AESGCM(clave)
    tx = [(n, p) for n, p in paquetes if p.startswith(b"AESGCM|")]
    print(f"[+] Transacciones cifradas encontradas: {len(tx)}\n")
    print("========== TRANSACCIONES ==========\n")
    for i, (n, p) in enumerate(tx, 1):
        c = p[len(b"AESGCM|"):]
        nonce, ct = c[:12], c[12:]
        try:
            msg = aes.decrypt(nonce, ct, None)   # lanza InvalidTag si falla la autenticación
            print(f"[Transacción {i}]  (paquete #{n}, autenticación OK)")
            print(msg.decode(), "\n")
        except Exception as e:
            print(f"[Transacción {i}] (paquete #{n}) FALLO de autenticación: {type(e).__name__}\n")


if __name__ == "__main__":
    main()