"""Punto de entrada del cifrador por bloques modularizado."""

from constants import LARGO_BLOQUE
from cipher_core import cifrar, descifrar


if __name__ == "__main__":
    max_len = LARGO_BLOQUE

    print("CIFRADOR POR BLOQUES")
    print(f"Ingrese un mensaje de 1 a {max_len} caracteres, sin espacios ni 'ñ'.")

    while True:
        mensaje = input("Mensaje a cifrar: ").strip()
        try:
            cifrado, clave, largo_original = cifrar(mensaje, verbose=False)
            recuperado = descifrar(cifrado, clave, largo_original, verbose=False)
            break
        except ValueError as exc:
            print(f"Entrada invalida: {exc}")
            print("Intente nuevamente.\n")

    print(f"mensaje: {mensaje}")
    print(f"clave: 0x{clave:016X}")
    print(f"cifrado: {cifrado}")
    print(f"descifrado: {recuperado}")
    print(f"verificacion: {'CORRECTO' if recuperado == mensaje else 'ERROR'}")
