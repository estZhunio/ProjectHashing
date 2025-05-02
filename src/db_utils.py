import sqlite3
import os
import datetime
import json
import hashlib


class HashDatabase:
    def __init__(self, db_path="hash_history.db"):
        """
        Inicializa la base de datos para almacenar hashes de forma profesional.

        Args:
            db_path (str): Ruta del archivo de base de datos SQLite
        """
        self.db_path = db_path
        self.initialize_db()
        self.migrate_if_needed()

    def initialize_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Tabla mejorada para almacenar hashes
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash_value TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_name TEXT,
            source_size INTEGER,
            timestamp TEXT NOT NULL,
            metadata TEXT,
            salt TEXT,
            created_by TEXT,
            is_truncated BOOLEAN DEFAULT 0,
            original_path TEXT,
            integrity_verified BOOLEAN DEFAULT 0
        )
        ''')

        # Tabla para configuración de privacidad
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS privacy_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_name TEXT UNIQUE,
            setting_value TEXT
        )
        ''')

        # Tabla para auditoría
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            hash_id INTEGER,
            timestamp TEXT,
            details TEXT
        )
        ''')

        # Insertar configuración predeterminada
        cursor.execute('''
        INSERT OR IGNORE INTO privacy_settings (setting_name, setting_value) 
        VALUES ('display_mode', 'educational')
        ''')

        conn.commit()
        conn.close()

    def migrate_if_needed(self):
        """Migra la base de datos si es necesario para añadir nuevas columnas"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Verificar si necesitamos migrar
        cursor.execute("PRAGMA table_info(hashes)")
        columns = [column[1] for column in cursor.fetchall()]

        new_columns = {
            'source_size': 'INTEGER',
            'metadata': 'TEXT',
            'salt': 'TEXT',
            'created_by': 'TEXT',
            'is_truncated': 'BOOLEAN DEFAULT 0',
            'original_path': 'TEXT',
            'integrity_verified': 'BOOLEAN DEFAULT 0'
        }

        for column_name, column_type in new_columns.items():
            if column_name not in columns:
                cursor.execute(f'ALTER TABLE hashes ADD COLUMN {column_name} {column_type}')

        conn.commit()
        conn.close()

    def save_hash(self, hash_value, algorithm, source_type, source_name="",
                  source_size=None, metadata=None, salt=None, created_by=None,
                  original_path=None):
        """
        Guarda un hash en la base de datos de forma profesional

        Args:
            hash_value (str): El valor hash calculado
            algorithm (str): Algoritmo usado
            source_type (str): 'text' o 'file'
            source_name (str): Nombre descriptivo de la fuente
            source_size (int, optional): Tamaño del contenido original
            metadata (dict, optional): Metadatos adicionales
            salt (str, optional): Sal utilizada (para contraseñas)
            created_by (str, optional): Usuario o sistema que creó el hash
            original_path (str, optional): Ruta original del archivo

        Returns:
            int: ID del registro insertado
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        timestamp = datetime.datetime.now().isoformat()
        metadata_json = json.dumps(metadata) if metadata else None

        cursor.execute("""
            INSERT INTO hashes (
                hash_value, algorithm, source_type, source_name, source_size, 
                timestamp, metadata, salt, created_by, original_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (hash_value, algorithm, source_type, source_name, source_size,
              timestamp, metadata_json, salt, created_by, original_path))

        last_id = cursor.lastrowid

        # Registrar en el log de auditoría
        self._log_action(cursor, 'CREATE', last_id, {'algorithm': algorithm})

        conn.commit()
        conn.close()

        return last_id

    def get_recent_hashes(self, limit=20, source_type=None, secure_mode=False):
        """
        Obtiene los hashes más recientes con opción de modo seguro

        Args:
            limit (int): Número máximo de registros a devolver
            source_type (str, optional): 'text', 'file' o None para todos
            secure_mode (bool): Si es True, oculta parte del hash

        Returns:
            list: Lista de diccionarios con los hashes
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
            SELECT * FROM hashes 
            {} 
            ORDER BY id DESC LIMIT ?
        """.format("WHERE source_type = ?" if source_type else "")

        if source_type:
            cursor.execute(query, (source_type, limit))
        else:
            cursor.execute(query, (limit,))

        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)

            # Parsear metadata si existe
            if row_dict['metadata']:
                row_dict['metadata'] = json.loads(row_dict['metadata'])

            # Aplicar modo seguro si está activado
            if secure_mode and row_dict['hash_value']:
                row_dict['hash_value'] = self._truncate_hash(row_dict['hash_value'])
                row_dict['is_truncated'] = True

            results.append(row_dict)

        conn.close()
        return results

    def _truncate_hash(self, hash_value):
        """Trunca un hash mostrando solo los primeros y últimos caracteres"""
        if len(hash_value) <= 8:
            return hash_value
        return f"{hash_value[:4]}...{hash_value[-4:]}"

    def verify_file_integrity(self, hash_id, filepath):
        """
        Verifica si un archivo actual coincide con su hash guardado

        Args:
            hash_id (int): ID del hash en la base de datos
            filepath (str): Ruta del archivo a verificar

        Returns:
            bool: True si el archivo coincide con el hash guardado
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT hash_value, algorithm FROM hashes WHERE id = ?",
            (hash_id,)
        )

        result = cursor.fetchone()
        if not result:
            conn.close()
            return False

        stored_hash, algorithm = result

        # Calcular el hash del archivo actual
        try:
            from src.hash_utils import calculate_hash_file
            current_hash = calculate_hash_file(filepath, algorithm)
            is_valid = current_hash == stored_hash

            # Actualizar el estado de verificación
            cursor.execute(
                "UPDATE hashes SET integrity_verified = ? WHERE id = ?",
                (is_valid, hash_id)
            )

            self._log_action(cursor, 'VERIFY', hash_id, {'result': is_valid})

            conn.commit()
            conn.close()

            return is_valid

        except Exception as e:
            conn.close()
            return False

    def export_history(self, format='json', filepath=None):
        """
        Exporta el historial en formato JSON o CSV

        Args:
            format (str): 'json' o 'csv'
            filepath (str, optional): Ruta donde guardar el archivo

        Returns:
            str: Ruta del archivo exportado o datos si no se especifica filepath
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM hashes ORDER BY id DESC")
        results = [dict(row) for row in cursor.fetchall()]

        conn.close()

        if format == 'json':
            json_data = json.dumps(results, indent=2)
            if filepath:
                with open(filepath, 'w') as f:
                    f.write(json_data)
                return filepath
            return json_data

        elif format == 'csv':
            import csv
            if not filepath:
                filepath = f"hash_history_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

            with open(filepath, 'w', newline='') as csvfile:
                if results:
                    writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
                    writer.writeheader()
                    writer.writerows(results)

            return filepath

    def _log_action(self, cursor, action, hash_id, details=None):
        """
        Registra una acción en el log de auditoría

        Args:
            cursor: Cursor de la base de datos
            action (str): Tipo de acción (CREATE, VERIFY, DELETE, etc.)
            hash_id (int): ID del hash relacionado
            details (dict, optional): Detalles adicionales de la acción
        """
        timestamp = datetime.datetime.now().isoformat()
        details_json = json.dumps(details) if details else None

        cursor.execute("""
            INSERT INTO audit_log (action, hash_id, timestamp, details)
            VALUES (?, ?, ?, ?)
        """, (action, hash_id, timestamp, details_json))

    def get_hash_by_id(self, hash_id):
        """
        Obtiene un hash específico por su ID

        Args:
            hash_id (int): ID del hash a buscar

        Returns:
            dict: Datos del hash o None si no se encuentra
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM hashes WHERE id = ?
        """, (hash_id,))

        result = cursor.fetchone()
        conn.close()

        if result:
            row_dict = dict(result)
            if row_dict['metadata']:
                row_dict['metadata'] = json.loads(row_dict['metadata'])
            return row_dict
        return None

    def delete_hash(self, hash_id):
        """
        Elimina un hash de la base de datos

        Args:
            hash_id (int): ID del hash a eliminar

        Returns:
            bool: True si se eliminó correctamente
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Registrar la acción antes de eliminar
            self._log_action(cursor, 'DELETE', hash_id)

            cursor.execute("DELETE FROM hashes WHERE id = ?", (hash_id,))
            success = cursor.rowcount > 0

            conn.commit()
            return success
        except Exception as e:
            conn.rollback()
            return False
        finally:
            conn.close()

    def get_audit_log(self, limit=50):
        """
        Obtiene el registro de auditoría

        Args:
            limit (int): Número máximo de registros a devolver

        Returns:
            list: Lista de registros de auditoría
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM audit_log 
            ORDER BY id DESC LIMIT ?
        """, (limit,))

        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            if row_dict['details']:
                row_dict['details'] = json.loads(row_dict['details'])
            results.append(row_dict)

        conn.close()
        return results

    def get_statistics(self):
        """
        Obtiene estadísticas de uso de la base de datos

        Returns:
            dict: Estadísticas de uso
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        # Total de hashes
        cursor.execute("SELECT COUNT(*) FROM hashes")
        stats['total_hashes'] = cursor.fetchone()[0]

        # Hashes por algoritmo
        cursor.execute("""
            SELECT algorithm, COUNT(*) as count 
            FROM hashes 
            GROUP BY algorithm
        """)
        stats['by_algorithm'] = dict(cursor.fetchall())

        # Hashes por tipo
        cursor.execute("""
            SELECT source_type, COUNT(*) as count 
            FROM hashes 
            GROUP BY source_type
        """)
        stats['by_type'] = dict(cursor.fetchall())

        # Hashes verificados
        cursor.execute("""
            SELECT COUNT(*) 
            FROM hashes 
            WHERE integrity_verified = 1
        """)
        stats['verified_hashes'] = cursor.fetchone()[0]

        conn.close()
        return stats

    def set_privacy_setting(self, setting_name, setting_value):
        """
        Establece una configuración de privacidad

        Args:
            setting_name (str): Nombre de la configuración
            setting_value (str): Valor de la configuración
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO privacy_settings (setting_name, setting_value)
            VALUES (?, ?)
        """, (setting_name, setting_value))

        conn.commit()
        conn.close()

    def get_privacy_setting(self, setting_name, default=None):
        """
        Obtiene una configuración de privacidad

        Args:
            setting_name (str): Nombre de la configuración
            default: Valor por defecto si no existe

        Returns:
            str: Valor de la configuración
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT setting_value 
            FROM privacy_settings 
            WHERE setting_name = ?
        """, (setting_name,))

        result = cursor.fetchone()
        conn.close()

        return result[0] if result else default