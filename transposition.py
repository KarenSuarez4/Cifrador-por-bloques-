"""Capa de transposicion directa e inversa."""


def _mcd(a: int, b: int) -> int:
    """Maximo comun divisor por Euclides."""
    while b:
        a, b = b, a % b
    return a


def _params_transposicion(K_r: int, n: int) -> tuple:
    """Calcula (paso, offset) de una permutacion biyectiva."""
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
    """Aplica permutacion de posiciones parametrizada por K_r."""
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
    """Reconstruye el bloque previo a la transposicion."""
    n = len(bloque)
    if n == 0:
        return bloque

    paso, offset = _params_transposicion(K_r, n)
    inv = "?" * n
    for j in range(n):
        fuente = (j * paso + offset) % n
        inv = inv[:fuente] + bloque[j] + inv[fuente + 1 :]
    return inv
