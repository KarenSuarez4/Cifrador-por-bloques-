"""Interfaz de línea de comandos del cifrador por bloques.

Este archivo implementa el flujo de ejecución interactivo:
- lectura y validación de entrada por medio del núcleo (`cipher_core.py`),
- ejecución de cifrado y descifrado,
- reporte de verificación de consistencia extremo a extremo.
"""

from constants import LARGO_BLOQUE
from cipher_core import cifrar, descifrar


if __name__ == "__main__":
    max_len = LARGO_BLOQUE

    print("CIFRADOR POR BLOQUES")
    print(f"Ingrese un mensaje de 1 a {max_len} caracteres, sin espacios ni 'ñ'.")

    while True:
        mensaje = input("Mensaje a cifrar: ").strip()
        try:
            cifrado, clave, largo_original = cifrar(mensaje, verbose=True)
            recuperado = descifrar(cifrado, clave, largo_original, verbose=True)
            break
        except ValueError as exc:
            print(f"Entrada invalida: {exc}")
            print("Intente nuevamente.\n")

    print(f"mensaje: {mensaje}")
    print(f"clave: 0x{clave:016X}")
    print(f"cifrado: {cifrado}")
    print(f"descifrado: {recuperado}")
    print(f"verificacion: {'CORRECTO' if recuperado == mensaje else 'ERROR'}")
