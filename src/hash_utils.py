# Añadir a hash_utils.py
import hashlib


def calculate_hash_string(text, algorithm):
    """
    Calcula el hash de una cadena de texto usando el algoritmo especificado.

    Argumentos: text (str):
        El texto para el que se calculará el hash
        algorithm (str): El algoritmo a utilizar (SHA-256, SHA-512, SHA-3, MD5)

    Returns:
        str: El hash calculado en formato hexadecimal
    """
    if algorithm == "SHA-256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif algorithm == "SHA-512":
        return hashlib.sha512(text.encode()).hexdigest()
    elif algorithm == "SHA-3":
        return hashlib.sha3_256(text.encode()).hexdigest()
    elif algorithm == "MD5":
        return hashlib.md5(text.encode()).hexdigest()
    else:
        raise ValueError(f"Algoritmo no reconocido: {algorithm}")


def calculate_hash_file(filepath, algorithm):
    """
    Calcula el hash de un archivo usando el algoritmo especificado.

    Args:
        filepath (str): Ruta al archivo para el que se calculará el hash
        algorithm (str): El algoritmo a utilizar (SHA-256, SHA-512, SHA-3, MD5)

    Returns:
        str: El hash calculado en formato hexadecimal
    """
    hash_obj = None

    if algorithm == "SHA-256":
        hash_obj = hashlib.sha256()
    elif algorithm == "SHA-512":
        hash_obj = hashlib.sha512()
    elif algorithm == "SHA-3":
        hash_obj = hashlib.sha3_256()
    elif algorithm == "MD5":
        hash_obj = hashlib.md5()
    else:
        raise ValueError(f"Algoritmo no reconocido: {algorithm}")

    with open(filepath, 'rb') as f:
        # Leer en bloques para archivos grandes
        for block in iter(lambda: f.read(4096), b''):
            hash_obj.update(block)

    return hash_obj.hexdigest()


def compare_hashes(hash1, hash2):
    """
    Compara dos hashes para verificar si son idénticos.

    Args:
        hash1 (str): Primer hash para comparar
        hash2 (str): Segundo hash para comparar

    Returns:
        bool: True si los hashes coinciden, False en caso contrario
    """
    return hash1.lower() == hash2.lower()