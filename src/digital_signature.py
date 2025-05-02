from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import base64


class DigitalSignatureManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self, key_size=2048):
        """Genera un par de claves RSA"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, # Este numero permite operaciones rápidas y seguras en RSA. Es el valor estándar recomendado
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()
        return True

    def sign_data(self, data, algorithm_name="SHA-256"):
        """Firma datos con la clave privada"""
        if not self.private_key:
            raise ValueError("No hay clave privada cargada")

        if isinstance(data, str):
            data = data.encode()

        hash_algorithm = self._get_hash_algorithm(algorithm_name)

        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hash_algorithm),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_algorithm
        )

        return base64.b64encode(signature).decode()

    def verify_signature(self, data, signature_b64):
        """Verifica una firma con la clave pública"""
        if not self.public_key:
            raise ValueError("No hay clave pública cargada")

        if isinstance(data, str):
            data = data.encode()

        signature = base64.b64decode(signature_b64) # Decodifsa la firma

        # Intentar verificar con diferentes algoritmos
        for algo in ["SHA-256", "SHA-512", "SHA-3"]:
            try:
                hash_algorithm = self._get_hash_algorithm(algo)
                self.public_key.verify(
                    signature,
                    data,
                    padding.PSS( # Metodo seguro para firmas.
                        mgf=padding.MGF1(hash_algorithm),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_algorithm # El hash del algoritmo
                )
                return True, algo  # Firma válida, retorna el algoritmo detectado
            except InvalidSignature:
                continue
            except Exception:
                continue

        return False, None  # Firma inválida

    def save_private_key(self, filepath, password=None):
        """Guarda la clave privada en un archivo"""
        if not self.private_key:
            raise ValueError("No hay clave privada para guardar")

        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())

        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

        with open(filepath, 'wb') as f:
            f.write(pem)

    def save_public_key(self, filepath):
        """Guarda la clave pública en un archivo"""
        if not self.public_key:
            raise ValueError("No hay clave pública para guardar")

        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(filepath, 'wb') as f:
            f.write(pem)

    def load_private_key(self, filepath, password=None):
        """Carga una clave privada desde un archivo"""
        with open(filepath, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None
            )
        self.public_key = self.private_key.public_key()

    def load_public_key(self, filepath):
        """Carga una clave pública desde un archivo"""
        with open(filepath, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read()) # Carga la clave privada

    def _get_hash_algorithm(self, algorithm_name):
        """Obtiene el objeto de algoritmo hash correspondiente"""
        if algorithm_name == "SHA-256":
            return hashes.SHA256()
        elif algorithm_name == "SHA-512":
            return hashes.SHA512()
        elif algorithm_name == "SHA-3":
            return hashes.SHA3_256()
        else:
            return hashes.SHA256()  # Default