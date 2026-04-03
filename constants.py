"""Constantes globales del cifrador."""

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
TAM_ALFA = 62

R = 32
LARGO_BLOQUE = 20
CHAR_PAD = "A"
MASK64 = (1 << 64) - 1

RONDAS_VERBOSE = (1, 16, 32)

A_S = 3
B_S = 17
A_INV = 21
