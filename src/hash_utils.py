import hashlib
import bcrypt
from argon2 import PasswordHasher
import blake3


def calculate_hash_string(text, algorithm):
    """
    Calcula el hash de una cadena de texto usando el algoritmo especificado.

    Argumentos:
        text (str): El texto para el que se calculará el hash
        algorithm (str): El algoritmo a utilizar
                        (SHA-256, SHA-512, SHA-3, SHA-1, MD5, bcrypt, Argon2, BLAKE2, BLAKE3)

    Returns:
        str: El hash calculado en formato hexadecimal (o formato específico del algoritmo)
    """
    if algorithm == "SHA-256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif algorithm == "SHA-512":
        return hashlib.sha512(text.encode()).hexdigest()
    elif algorithm == "SHA-3":
        return hashlib.sha3_256(text.encode()).hexdigest()
    elif algorithm == "SHA-1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif algorithm == "MD5":
        return hashlib.md5(text.encode()).hexdigest()
    elif algorithm == "bcrypt":
        # bcrypt requiere una sal (salt) y retorna bytes
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(text.encode(), salt).decode()
    elif algorithm == "Argon2":
        # Argon2 es lo más moderno para contraseñas
        ph = PasswordHasher()
        return ph.hash(text)
    elif algorithm == "BLAKE2":
        return hashlib.blake2b(text.encode()).hexdigest()
    elif algorithm == "BLAKE3":
        return blake3.blake3(text.encode()).hexdigest()
    else:
        raise ValueError(f"Algoritmo no reconocido: {algorithm}")


def calculate_hash_file(filepath, algorithm):
    """
    Calcula el hash de un archivo usando el algoritmo especificado.

    Args:
        filepath (str): Ruta al archivo para el que se calculará el hash
        algorithm (str): El algoritmo a utilizar
                        (SHA-256, SHA-512, SHA-3, SHA-1, MD5, BLAKE2, BLAKE3)

    Note: bcrypt y Argon2 no son adecuados para archivos

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
    elif algorithm == "SHA-1":
        hash_obj = hashlib.sha1()
    elif algorithm == "MD5":
        hash_obj = hashlib.md5()
    elif algorithm == "BLAKE2":
        hash_obj = hashlib.blake2b()
    elif algorithm == "BLAKE3":
        hash_obj = blake3.blake3()
    elif algorithm in ["bcrypt", "Argon2"]:
        raise ValueError(f"{algorithm} no es adecuado para archivos, solo para contraseñas")
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


def verify_password_hash(password, hashed, algorithm):
    """
    Verifica si una contraseña coincide con su hash (para bcrypt y Argon2).

    Args:
        password (str): Contraseña en texto plano para verificar
        hashed (str): Hash almacenado
        algorithm (str): Algoritmo usado (bcrypt o Argon2)

    Returns:
        bool: True si la contraseña coincide, False en caso contrario
    """
    if algorithm == "bcrypt":
        return bcrypt.checkpw(password.encode(), hashed.encode())
    elif algorithm == "Argon2":
        ph = PasswordHasher()
        try:
            ph.verify(hashed, password)
            return True
        except:
            return False
    else:
        raise ValueError(f"Algorithm {algorithm} no soporta verificación de contraseñas")