"""Parámetros globales y constantes criptográficas del sistema.

Este módulo centraliza la configuración inmutable del cifrador por bloques:
- dominio de símbolos permitido,
- tamaño de bloque y cantidad de rondas,
- constantes numéricas de la S-Box,
- máscara de 64 bits para operaciones con enteros.

Su objetivo es desacoplar los valores de configuración de la lógica de negocio
implementada en los módulos de cifrado, sustitución, transposición y claves.
"""

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
