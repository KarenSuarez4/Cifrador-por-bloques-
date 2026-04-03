"""Analisis de avalancha, rondas y resumen criptografico."""

from cipher_core import cifrar
from constants import ALFABETO, R, TAM_ALFA
from key_schedule import expandir_subclave, generar_clave
from padding import aplicar_padding
from substitution import sustitucion
from transposition import transposicion


def analisis_avalancha(M: str) -> None:
    """Mide cambios en C cuando cambia solo un caracter de M."""
    C1, _ = cifrar(M, verbose=False)

    idx0 = ALFABETO.index(M[0])
    M2 = ALFABETO[(idx0 + 1) % TAM_ALFA] + M[1:]
    C2, _ = cifrar(M2, verbose=False)

    diff = sum(1 for a, b in zip(C1, C2) if a != b)
    ratio = diff / len(C1)

    print("\n" + "=" * 67)
    print("   ANALISIS DE AVALANCHA")
    print("=" * 67)
    print(f"   M1 = '{M}'")
    print(f"   C1 = '{C1}'")
    print()
    print(f"   M2 = '{M2}'  <- solo M[0] cambiado ({M[0]} -> {M2[0]})")
    print(f"   C2 = '{C2}'")
    print()
    print(f"   Simbolos distintos  : {diff} / {len(C1)}  ({100 * ratio:.1f}%)")
    veredicto = "CUMPLIDO" if ratio >= 0.5 else "Insuficiente - aumentar R"
    print(f"   Avalancha >= 50%    : {veredicto}")
    print("=" * 67)


def analisis_rondas(M: str) -> None:
    """Compara estados parciales contra el estado final de 32 rondas."""
    C_final, _ = cifrar(M, verbose=False)

    K = generar_clave(M)
    estado = aplicar_padding(M)

    print("\n" + "=" * 67)
    print("   ANALISIS DE IMPACTO - NUMERO DE RONDAS")
    print("=" * 67)
    print(f"   Mensaje M = '{M}'")
    print(f"   C_final (R=32) = '{C_final}'")
    print()
    print(f"   {'Rondas':>7}  {'Estado parcial':>22}  {'Delta vs R=32':>13}  Progreso")
    print("   " + "-" * 68)

    HITOS = (1, 2, 4, 8, 12, 16, 20, 24, 28, 32)

    for r in range(1, R + 1):
        K_r = expandir_subclave(K, r)
        estado = transposicion(sustitucion(estado, K_r), K_r)

        if r in HITOS:
            diff = sum(1 for a, b in zip(estado, C_final) if a != b)
            pct = 100 * diff / len(C_final)
            barras = int(pct / 5)
            barra = "#" * barras + "." * (20 - barras)
            print(f"   {r:>7}  {estado}  {diff:>3}/{len(C_final)}          [{barra}]")

    print("=" * 67)


def imprimir_resumen_criptografico() -> None:
    """Imprime el resumen teorico para el entregable."""
    print("""
=======================================================================
   ANALISIS CRIPTOGRAFICO - PRINCIPIOS DE SHANNON Y RESISTENCIA
=======================================================================

1. CONFUSION (Sustitucion S)
   S(i) = (3*i + 17) mod 62
   Mezcla de clave: idx_f = (S(i) + k_i) mod 62

2. DIFUSION (Transposicion pi)
   pi_r(j) = (j*paso + offset) mod 20, con mcd(paso, 20) = 1

3. KEY SCHEDULE
   K = f(M) con rotaciones y operaciones bit a bit
   K_r = ROTL64(K, r*3) XOR (r * constante_e)

4. RESISTENCIA DIFERENCIAL (academica)
   P_total aproximada <= (1/62)^32

5. RESISTENCIA LINEAL (academica)
   La combinacion S afine + suma modular reduce correlaciones lineales utiles.

6. RONDAS
   R = 32 aporta margen de seguridad adicional para difusion completa.

LIMITACION IMPORTANTE
   Este esquema no incluye autenticacion (MAC/AEAD), por lo que no garantiza
   integridad criptografica fuerte ante manipulacion activa.
=======================================================================
""")
