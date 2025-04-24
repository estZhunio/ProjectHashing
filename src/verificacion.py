# verificacion.py
from src.hash_utils import calculate_hash_string, calculate_hash_file, compare_hashes
import os


def verificar_integridad_texto(texto, hash_referencia, algoritmo):
    """
    Verifica la integridad de un texto comparando su hash con un hash de referencia.

    Args:
        texto (str): El texto cuya integridad se verificará
        hash_referencia (str): El hash de referencia para la comparación
        algoritmo (str): El algoritmo a utilizar (SHA-256, SHA-512, MD5)

    Returns:
        tuple: (bool, str) - Un booleano indicando si la verificación fue exitosa y el hash calculado
    """
    hash_calculado = calculate_hash_string(texto, algoritmo)
    es_valido = compare_hashes(hash_calculado, hash_referencia)

    return es_valido, hash_calculado


def verificar_integridad_archivo(ruta_archivo, hash_referencia, algoritmo):
    """
    Verifica la integridad de un archivo comparando su hash con un hash de referencia.

    Args:
        ruta_archivo (str): Ruta al archivo cuya integridad se verificará
        hash_referencia (str): El hash de referencia para la comparación
        algoritmo (str): El algoritmo a utilizar (SHA-256, SHA-512, MD5)

    Returns:
        tuple: (bool, str) - Un booleano indicando si la verificación fue exitosa y el hash calculado
    """
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(f"El archivo '{ruta_archivo}' no existe")

    hash_calculado = calculate_hash_file(ruta_archivo, algoritmo)
    es_valido = compare_hashes(hash_calculado, hash_referencia)

    return es_valido, hash_calculado