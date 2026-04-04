# Cifrador por bloques

Implementación de un cifrador por bloques de tamaño fijo sobre alfabeto alfanumérico ASCII.
El sistema aplica 32 rondas de sustitución + transposición con subclaves derivadas de una clave maestra de 64 bits.

## Flujo general

1. Se valida el mensaje de entrada (solo caracteres del alfabeto permitido).
2. Se aplica padding hasta completar 20 caracteres.
3. Se genera una clave maestra de 64 bits a partir del mensaje.
4. Se ejecutan 32 rondas de:
	- sustitución no lineal por posición,
	- transposición biyectiva dependiente de subclave.
5. Para descifrar, se aplican las operaciones inversas en orden inverso.

## Documentación por archivo

### `constants.py`
- Define parámetros globales del algoritmo: alfabeto, tamaño de bloque, número de rondas, máscara de 64 bits y constantes de la S-Box.
- Centraliza configuración criptográfica para evitar valores "hardcoded" en otros módulos.

### `bit_utils.py`
- Proporciona utilidades de bajo nivel sobre enteros de 64 bits.
- `rotl64`: rotación circular izquierda en 64 bits.
- `clave_posicion`: deriva el valor de mezcla para cada posición del bloque a partir de una subclave de ronda.

### `key_schedule.py`
- Implementa el esquema de clave.
- `generar_clave`: construye la clave maestra de 64 bits combinando rotaciones, desplazamientos y XOR con cada carácter del mensaje.
- `expandir_subclave`: deriva la subclave de cada ronda desde la clave maestra.

### `padding.py`
- Gestiona el ajuste del mensaje al tamaño fijo de bloque.
- `aplicar_padding`: completa con `CHAR_PAD` hasta 20 caracteres.
- `quitar_padding`: recupera el mensaje original usando su longitud real.

### `substitution.py`
- Implementa la capa de sustitución y su inversa.
- Usa una S-Box afín módulo 62 y mezcla dependiente de clave por posición.
- `sustitucion`: transforma cada símbolo del bloque.
- `sustitucion_inversa`: revierte exactamente la transformación.

### `transposition.py`
- Implementa la permutación de posiciones y su inversa.
- Calcula parámetros `(paso, offset)` dependientes de subclave, garantizando biyección mediante coprimalidad (`mcd(paso, n) = 1`).
- `transposicion`: reordena índices del bloque.
- `transposicion_inversa`: reconstruye el orden original.

### `cipher_core.py`
- Núcleo del cifrado/descifrado y API principal del proyecto.
- `cifrar(M)`: valida entrada, aplica padding, genera clave maestra y ejecuta las 32 rondas.
- `descifrar(C, K, M_len)`: ejecuta rondas inversas y remueve padding.
- Expone modo `verbose` para trazabilidad de rondas seleccionadas.

### `main.py`
- Punto de entrada interactivo por consola.
- Solicita mensaje, ejecuta cifrado y descifrado, y muestra verificación final de integridad (`recuperado == mensaje`).

## Restricciones de entrada

- Longitud del mensaje: 1 a 20 caracteres.
- Caracteres permitidos: `A-Z`, `a-z`, `0-9`.
- No se permiten espacios ni caracteres fuera del alfabeto definido.

## Resultado esperado

Para una entrada válida, el programa entrega:
- texto cifrado,
- clave maestra en hexadecimal,
- texto descifrado,
- estado de verificación.
