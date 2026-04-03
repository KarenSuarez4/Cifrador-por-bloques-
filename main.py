"""Punto de entrada del cifrador por bloques modularizado."""

from analysis_tools import analisis_avalancha, analisis_rondas, imprimir_resumen_criptografico
from cipher_core import cifrar, descifrar


if __name__ == "__main__":
    print()
    M1 = "PKG2024ABC99XZ"
    C1, _ = cifrar(M1, verbose=True)

    M1_rec = descifrar(C1, M1, verbose=True)
    ok1 = M1_rec == M1
    print(f"\n   Verificacion cifrado/descifrado: {'CORRECTO' if ok1 else 'ERROR'}\n")

    print("\n" + "-" * 67)
    print("   EJEMPLO 2: Mensaje corto con padding")
    print("-" * 67)
    M2 = "TRACK01"
    C2, _ = cifrar(M2, verbose=True)
    M2_rec = descifrar(C2, M2, verbose=True)
    print(f"\n   Verificacion cifrado/descifrado: {'CORRECTO' if M2_rec == M2 else 'ERROR'}\n")

    analisis_avalancha(M1)
    analisis_rondas(M1)
    imprimir_resumen_criptografico()
