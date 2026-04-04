"""Capa de transposición (permutación) del cifrador por bloques.

La permutación se parametriza por subclave de ronda y garantiza biyección
forzando coprimalidad entre el paso y la longitud del bloque.
"""


def _mcd(a: int, b: int) -> int:
    """Calcula el máximo común divisor mediante algoritmo de Euclides."""
    while b:
        a, b = b, a % b
    return a


def _params_transposicion(K_r: int, n: int) -> tuple:
    """Deriva parámetros de permutación válidos para longitud `n`.

    Args:
        K_r: Subclave de ronda.
        n: Longitud del bloque.

    Returns:
        Tupla `(paso, offset)` que define una permutación biyectiva.
    """
    paso = int((K_r & 0xFF) % n)
    if paso == 0:
        paso = 1

    cnt = 0
    while _mcd(paso, n) != 1:
        paso = (paso + 1) % n
        if paso == 0:
            paso = 1
        cnt += 1
        if cnt > n:
            paso = 1
            break

    offset = int((K_r >> 8) % n)
    return paso, offset


def transposicion(bloque: str, K_r: int) -> str:
    """Aplica permutación de posiciones parametrizada por subclave.

    Args:
        bloque: Estado de entrada.
        K_r: Subclave de ronda.

    Returns:
        Estado con símbolos reordenados.
    """
    n = len(bloque)
    if n == 0:
        return bloque

    paso, offset = _params_transposicion(K_r, n)
    resultado = ""
    for j in range(n):
        fuente = (j * paso + offset) % n
        resultado += bloque[fuente]
    return resultado


def transposicion_inversa(bloque: str, K_r: int) -> str:
    """Revierte la permutación aplicada en `transposicion`.

    Args:
        bloque: Estado transpuesto.
        K_r: Subclave de ronda usada en la fase directa.

    Returns:
        Estado original antes de la transposición.
    """
    n = len(bloque)
    if n == 0:
        return bloque

    paso, offset = _params_transposicion(K_r, n)
    inv = "?" * n
    for j in range(n):
        fuente = (j * paso + offset) % n
        inv = inv[:fuente] + bloque[j] + inv[fuente + 1 :]
    return inv
