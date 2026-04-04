"""Utilidades bit a bit usadas por el esquema de subclaves.

Responsabilidad arquitectónica:
- encapsular operaciones sobre palabras de 64 bits,
- exponer funciones auxiliares puras reutilizables por `key_schedule.py`
    y `substitution.py`.
"""

from constants import MASK64, TAM_ALFA


def rotl64(x: int, n: int) -> int:
    """Rota `x` a la izquierda en un espacio de 64 bits.

    Args:
        x: Entero de entrada.
        n: Número de posiciones a rotar.

    Returns:
        Entero rotado, acotado al rango de 64 bits.
    """
    n = n % 64
    if n == 0:
        return x & MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


def clave_posicion(K_r: int, i: int) -> int:
    """Deriva la mezcla de clave para la posición `i` del bloque.

    La derivación rota la subclave de ronda y proyecta el resultado sobre
    el tamaño del alfabeto para obtener un índice válido en `ALFABETO`.

    Args:
        K_r: Subclave de ronda de 64 bits.
        i: Posición del símbolo dentro del bloque.

    Returns:
        Valor entero en el rango [0, TAM_ALFA - 1].
    """
    Kr_rot = rotl64(K_r, i * 3)
    return Kr_rot % TAM_ALFA
