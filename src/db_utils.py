# db_utils.py
import sqlite3
import os
import datetime


class HashDatabase:
    def __init__(self, db_path="hash_history.db"):
        """
        Inicializa la base de datos para almacenar hashes.

        Args:
            db_path (str): Ruta del archivo de base de datos SQLite
        """
        self.db_path = db_path
        self.initialize_db()

    def initialize_db(self):
        # Crea las tablas necesarias si no existen
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Crear tabla para almacenar hashes
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash_value TEXT,
            algorithm TEXT,
            source_type TEXT,  -- 'text' o 'file'
            source_name TEXT,  -- Nombre descriptivo (puede ser el nombre del archivo o una descripción corta)
            timestamp TEXT
        )
        ''')

        conn.commit()
        conn.close()

    def save_hash(self, hash_value, algorithm, source_type, source_name=""):
        """
        Guarda un hash en la base de datos

        Args:
            hash_value (str): El valor hash calculado
            algorithm (str): Algoritmo usado
            source_type (str): 'text' o 'file'
            source_name (str): Nombre descriptivo de la fuente

        Returns:
            int: ID del registro insertado
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        timestamp = datetime.datetime.now().isoformat()

        cursor.execute(
            "INSERT INTO hashes (hash_value, algorithm, source_type, source_name, timestamp) VALUES (?, ?, ?, ?, ?)",
            (hash_value, algorithm, source_type, source_name, timestamp)
        )

        last_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return last_id

    def get_recent_hashes(self, limit=20, source_type=None):
        """
        Obtiene los hashes más recientes, opcionalmente filtrados por tipo

        Args:
            limit (int): Número máximo de registros a devolver
            source_type (str, optional): 'text', 'file' o None para todos

        Returns:
            list: Lista de tuplas con los hashes
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if source_type:
            cursor.execute(
                "SELECT id, hash_value, algorithm, source_type, source_name, timestamp FROM hashes WHERE source_type = ? ORDER BY id DESC LIMIT ?",
                (source_type, limit)
            )
        else:
            cursor.execute(
                "SELECT id, hash_value, algorithm, source_type, source_name, timestamp FROM hashes ORDER BY id DESC LIMIT ?",
                (limit,)
            )

        results = cursor.fetchall()
        conn.close()

        return results

    def get_hash_by_id(self, hash_id):
        """
        Obtiene un hash específico por su ID

        Args:
            hash_id (int): ID del hash a buscar

        Returns:
            tuple: Datos del hash o None si no se encuentra
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, hash_value, algorithm, source_type, source_name, timestamp FROM hashes WHERE id = ?",
            (hash_id,)
        )

        result = cursor.fetchone()
        conn.close()

        return result