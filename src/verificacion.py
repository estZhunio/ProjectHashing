from src.hash_utils import calculate_hash_string, calculate_hash_file, compare_hashes
import os
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


def verificar_integridad_texto(texto, hash_referencia, algoritmo):
    """
    Verifica la integridad de un texto comparando su hash con un hash de referencia.

    Args:
        texto (str): El texto cuya integridad se verificará
        hash_referencia (str): El hash de referencia para la comparación
        algoritmo (str): El algoritmo a utilizar

    Returns:
        tuple: (bool, str) - Un booleano indicando si la verificación fue exitosa y el hash calculado
    """
    # Para bcrypt y Argon2, usamos sus propias funciones de verificación
    if algoritmo == "bcrypt":
        try:
            # bcrypt.checkpw verifica usando la sal del hash original
            es_valido = bcrypt.checkpw(texto.encode(), hash_referencia.encode())
            return es_valido, hash_referencia  # Devolvemos el mismo hash porque no se puede recalcular
        except:
            return False, hash_referencia

    elif algoritmo == "Argon2":
        try:
            ph = PasswordHasher()
            ph.verify(hash_referencia, texto)
            return True, hash_referencia
        except VerifyMismatchError:
            return False, hash_referencia
        except:
            return False, hash_referencia

    else:
        # Para otros algoritmos, calculamos y comparamos normalmente
        hash_calculado = calculate_hash_string(texto, algoritmo)
        es_valido = compare_hashes(hash_calculado, hash_referencia)
        return es_valido, hash_calculado


def verificar_integridad_archivo(ruta_archivo, hash_referencia, algoritmo):
    """
    Verifica la integridad de un archivo comparando su hash con un hash de referencia.

    Args:
        ruta_archivo (str): Ruta al archivo cuya integridad se verificará
        hash_referencia (str): El hash de referencia para la comparación
        algoritmo (str): El algoritmo a utilizar

    Returns:
        tuple: (bool, str) - Un booleano indicando si la verificación fue exitosa y el hash calculado
    """
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(f"El archivo '{ruta_archivo}' no existe")

    # bcrypt y Argon2 no son adecuados para archivos
    if algoritmo in ["bcrypt", "Argon2"]:
        raise ValueError(f"{algoritmo} no es adecuado para verificar archivos")

    hash_calculado = calculate_hash_file(ruta_archivo, algoritmo)
    es_valido = compare_hashes(hash_calculado, hash_referencia)

    return es_valido, hash_calculado