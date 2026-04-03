"""Capa de sustitucion directa e inversa."""

from bit_utils import clave_posicion
from constants import ALFABETO, A_INV, A_S, B_S, TAM_ALFA


def s_box(idx: int) -> int:
    """S-Box base: S(i) = (3*i + 17) mod 62."""
    return (A_S * idx + B_S) % TAM_ALFA


def s_box_inv(idx: int) -> int:
    """Inversa: S^-1(j) = (21*(j - 17)) mod 62."""
    return (A_INV * (idx - B_S)) % TAM_ALFA


def sustitucion(bloque: str, K_r: int) -> str:
    """Aplica sustitucion con mezcla de clave por posicion."""
    resultado = ""
    for i in range(len(bloque)):
        idx = ALFABETO.index(bloque[i])
        idx_s = s_box(idx)
        k_i = clave_posicion(K_r, i)
        idx_f = (idx_s + k_i) % TAM_ALFA
        resultado += ALFABETO[idx_f]
    return resultado


def sustitucion_inversa(bloque: str, K_r: int) -> str:
    """Deshace sustitucion: resta modular y aplica S-Box inversa."""
    resultado = ""
    for i in range(len(bloque)):
        idx_f = ALFABETO.index(bloque[i])
        k_i = clave_posicion(K_r, i)
        idx_s = (idx_f - k_i) % TAM_ALFA
        idx = s_box_inv(idx_s)
        resultado += ALFABETO[idx]
    return resultado
