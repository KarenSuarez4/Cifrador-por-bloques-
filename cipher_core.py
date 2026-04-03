"""API principal de cifrado y descifrado."""

from constants import ALFABETO, LARGO_BLOQUE, R, RONDAS_VERBOSE
from key_schedule import expandir_subclave, generar_clave
from padding import aplicar_padding, quitar_padding
from substitution import sustitucion, sustitucion_inversa
from transposition import transposicion, transposicion_inversa


def cifrar(M: str, verbose: bool = True) -> tuple:
    """Cifra M y retorna (ciphertext, largo_original)."""
    M = M.strip()
    if not (1 <= len(M) <= LARGO_BLOQUE):
        raise ValueError(f"M debe tener entre 1 y {LARGO_BLOQUE} caracteres.")
    for c in M:
        if c not in ALFABETO:
            raise ValueError(
                f"Caracter no permitido: '{c}'. "
                "Solo alfanumericos ASCII (A-Z, a-z, 0-9)."
            )

    M_len = len(M)

    if verbose:
        sep = "=" * 67
        print(sep)
        print("   CIFRADOR DE BLOQUES - SISTEMA LOGISTICO DE SEGUIMIENTO")
        print(sep)
        print(f"   Mensaje original M  : '{M}'  (largo: {M_len})")

    bloque = aplicar_padding(M)
    if verbose:
        print(f"   Bloque con padding  : '{bloque}'  (largo: {len(bloque)})")

    K = generar_clave(M)
    if verbose:
        print(f"   Clave maestra K     : 0x{K:016X}")
        print(f"   Rondas R            : {R}")
        print("-" * 67)

    estado = bloque
    for r in range(1, R + 1):
        K_r = expandir_subclave(K, r)
        estado_s = sustitucion(estado, K_r)
        estado_t = transposicion(estado_s, K_r)
        estado = estado_t

        if verbose and r in RONDAS_VERBOSE:
            print(f"   [Ronda {r:02d}] K_r = 0x{K_r:016X}")
            print(f"              Post-Sustitucion  : '{estado_s}'")
            print(f"              Post-Transposicion: '{estado_t}'")
            print("-" * 67)

    C = estado
    if verbose:
        print(f"\n   >>> CIPHERTEXT C = '{C}'")
        print("=" * 67)

    return C, M_len


def descifrar(C: str, M_original: str, verbose: bool = True) -> str:
    """Descifra C usando la clave regenerada desde M_original."""
    K = generar_clave(M_original)
    M_len = len(M_original.strip())

    if verbose:
        print("\n" + "=" * 67)
        print("   DESCIFRADO")
        print(f"   Ciphertext de entrada : '{C}'")
        print("-" * 67)

    estado = C
    for r in range(R, 0, -1):
        K_r = expandir_subclave(K, r)
        estado = transposicion_inversa(estado, K_r)
        estado = sustitucion_inversa(estado, K_r)

    M_rec = quitar_padding(estado, M_len)

    if verbose:
        print(f"   Bloque descifrado     : '{estado}'")
        print(f"   Mensaje recuperado    : '{M_rec}'")
        print("=" * 67)

    return M_rec
