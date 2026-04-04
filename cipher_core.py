"""Núcleo de orquestación del cifrado por bloques.

Responsabilidad arquitectónica:
- validar entrada de usuario,
- coordinar padding, schedule de claves y capas de ronda,
- exponer API pública de cifrado/descifrado para `main.py`.
"""

from constants import ALFABETO, LARGO_BLOQUE, R, RONDAS_VERBOSE
from key_schedule import expandir_subclave, generar_clave
from padding import aplicar_padding, quitar_padding
from substitution import sustitucion, sustitucion_inversa
from transposition import transposicion, transposicion_inversa


def cifrar(M: str, verbose: bool = True) -> tuple:
    """Cifra un mensaje en un bloque de salida de longitud fija.

    Args:
        M: Mensaje a cifrar.
        verbose: Si es `True`, imprime estados en rondas seleccionadas.

    Returns:
        Tupla `(C, K, M_len)` donde:
        - `C` es el ciphertext final,
        - `K` es la clave maestra generada,
        - `M_len` es la longitud original del mensaje.

    Raises:
        ValueError: Si el mensaje no cumple longitud o alfabeto permitido.
    """
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
    bloque = aplicar_padding(M)

    K = generar_clave(M)

    estado = bloque
    for r in range(1, R + 1):
        estado_in = estado
        K_r = expandir_subclave(K, r)
        estado_s = sustitucion(estado_in, K_r)
        estado_t = transposicion(estado_s, K_r)
        estado = estado_t

        if verbose and r in RONDAS_VERBOSE:
            print(f"[CIF][R{r:02d}] K_r=0x{K_r:016X}")
            print(f"  entrada : {estado_in}")
            print(f"  sub     : {estado_s}")
            print(f"  transp  : {estado_t}")

    C = estado

    return C, K, M_len


def descifrar(C: str, K: int, M_len: int, verbose: bool = True) -> str:
    """Descifra un bloque cifrado usando la clave maestra de cifrado.

    Args:
        C: Bloque cifrado.
        K: Clave maestra de 64 bits usada en `cifrar`.
        M_len: Longitud real del mensaje original.
        verbose: Si es `True`, imprime estados en rondas seleccionadas.

    Returns:
        Mensaje recuperado sin padding.

    Raises:
        ValueError: Si `M_len` está fuera del rango de bloque.
    """
    if not (1 <= M_len <= LARGO_BLOQUE):
        raise ValueError(f"M_len debe estar entre 1 y {LARGO_BLOQUE}.")

    estado = C
    for r in range(R, 0, -1):
        estado_in = estado
        K_r = expandir_subclave(K, r)
        estado_tinv = transposicion_inversa(estado_in, K_r)
        estado_sinv = sustitucion_inversa(estado_tinv, K_r)
        estado = estado_sinv

        if verbose and r in RONDAS_VERBOSE:
            print(f"[DEC][R{r:02d}] K_r=0x{K_r:016X}")
            print(f"  entrada : {estado_in}")
            print(f"  t_inv   : {estado_tinv}")
            print(f"  s_inv   : {estado_sinv}")

    return quitar_padding(estado, M_len)
