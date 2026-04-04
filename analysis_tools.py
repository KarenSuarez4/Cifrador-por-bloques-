"""Utilidades de análisis mantenidas sin salida por consola."""

from cipher_core import cifrar
from constants import ALFABETO, R, TAM_ALFA
from key_schedule import expandir_subclave, generar_clave
from padding import aplicar_padding
from substitution import sustitucion
from transposition import transposicion


def analisis_avalancha(M: str) -> dict:
    """Calcula el impacto de un cambio de un caracter en el ciphertext."""
    C1, _ = cifrar(M, verbose=False)

    idx0 = ALFABETO.index(M[0])
    M2 = ALFABETO[(idx0 + 1) % TAM_ALFA] + M[1:]
    C2, _ = cifrar(M2, verbose=False)

    diff = sum(1 for a, b in zip(C1, C2) if a != b)
    ratio = diff / len(C1)
    veredicto = "CUMPLIDO" if ratio >= 0.5 else "Insuficiente - aumentar R"

    return {
        "M1": M,
        "C1": C1,
        "M2": M2,
        "C2": C2,
        "simbolos_distintos": diff,
        "porcentaje_diferente": 100 * ratio,
        "veredicto": veredicto,
    }


def analisis_rondas(M: str) -> dict:
   """Compara estados parciales contra el estado final de 32 rondas."""
   C_final, _ = cifrar(M, verbose=False)

   K = generar_clave(M)
   estado = aplicar_padding(M)
   HITOS = (1, 2, 4, 8, 12, 16, 20, 24, 28, 32)
   avances = []

   for r in range(1, R + 1):
      K_r = expandir_subclave(K, r)
      estado = transposicion(sustitucion(estado, K_r), K_r)

      if r in HITOS:
         diff = sum(1 for a, b in zip(estado, C_final) if a != b)
         pct = 100 * diff / len(C_final)
         avances.append(
               {
                 "rondas": r,
                 "estado_parcial": estado,
                 "delta_vs_final": diff,
                 "longitud_final": len(C_final),
                 "porcentaje_diferente": pct,
               }
         )

      return {
         "mensaje": M,
         "cifrado_final": C_final,
         "avances": avances,
      }
