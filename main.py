"""Punto de entrada del cifrador por bloques modularizado."""

from cipher_core import cifrar, descifrar


if __name__ == "__main__":
    mensajes = ["PKG2024ABC99XZ", "TRACK01"]

    for mensaje in mensajes:
        cifrado, clave = cifrar(mensaje, verbose=False)
        recuperado = descifrar(cifrado, clave, verbose=False)

        print(f"mensaje: {mensaje}")
        print(f"clave: 0x{clave:016X}")
        print(f"cifrado: {cifrado}")
        print(f"descifrado: {recuperado}")
        print(f"verificacion: {'CORRECTO' if recuperado == mensaje else 'ERROR'}")
        print()
