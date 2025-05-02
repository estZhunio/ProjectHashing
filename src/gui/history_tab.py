import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
import json
from src.db_utils import HashDatabase


class HistoryTab:
    def __init__(self, parent, algorithms, status_var):
        self.parent = parent
        self.algorithms = algorithms
        self.status_var = status_var
        self.db = HashDatabase()
        self.secure_mode = False

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Header con controles de seguridad
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_frame, text="Historial de Hashing", style='Header.TLabel').pack(side=tk.LEFT)

        # Toggle modo seguro
        self.secure_mode_var = tk.BooleanVar(value=False)
        secure_check = ttk.Checkbutton(header_frame, text="Modo Seguro",
                                       variable=self.secure_mode_var,
                                       command=self.toggle_secure_mode)
        secure_check.pack(side=tk.RIGHT, padx=10)

        # Tabla principal
        columns = ("ID", "Tipo", "Fuente", "Hash", "Algoritmo", "Tamaño", "Fecha")
        self.history_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)

        # Configurar columnas
        self.history_tree.heading("ID", text="ID")
        self.history_tree.heading("Tipo", text="Tipo")
        self.history_tree.heading("Fuente", text="Fuente")
        self.history_tree.heading("Hash", text="Hash")
        self.history_tree.heading("Algoritmo", text="Algoritmo")
        self.history_tree.heading("Tamaño", text="Tamaño")
        self.history_tree.heading("Fecha", text="Fecha")

        self.history_tree.column("ID", width=40, anchor=tk.CENTER)
        self.history_tree.column("Tipo", width=60, anchor=tk.CENTER)
        self.history_tree.column("Fuente", width=150)
        self.history_tree.column("Hash", width=350)
        self.history_tree.column("Algoritmo", width=80, anchor=tk.CENTER)
        self.history_tree.column("Tamaño", width=80, anchor=tk.CENTER)
        self.history_tree.column("Fecha", width=150)

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscroll=scrollbar.set)

        # Empaquetar
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Panel de detalles
        details_frame = ttk.LabelFrame(frame, text="Detalles del Hash", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.details_text = scrolledtext.ScrolledText(details_frame, height=8, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)

        # Botones de acción
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=5)

        copy_hash_btn = ttk.Button(button_frame, text="Copiar Hash",
                                   command=self.copy_selected_hash)
        copy_hash_btn.pack(side=tk.LEFT, padx=5)

        refresh_btn = ttk.Button(button_frame, text="Actualizar",
                                 command=self.load_history)
        refresh_btn.pack(side=tk.RIGHT, padx=5)

        # Vincular eventos
        self.history_tree.bind('<<TreeviewSelect>>', self.on_select)

        # Cargar datos iniciales
        self.load_history()

    def toggle_secure_mode(self):
        """Alterna entre modo seguro y normal"""
        self.secure_mode = self.secure_mode_var.get()
        self.load_history()
        self.status_var.set(f"Modo {'seguro' if self.secure_mode else 'normal'} activado")

    def load_history(self):
        """Carga el historial con opciones de seguridad"""
        # Limpiar árbol existente
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        # Cargar datos con modo seguro si está activado
        hashes = self.db.get_recent_hashes(limit=100, secure_mode=self.secure_mode)

        for hash_data in hashes:
            # Formatear tamaño
            size = self.format_size(hash_data.get('source_size', 0)) if hash_data.get('source_size') else "-"

            # Formatear fecha
            timestamp = hash_data['timestamp'].split('T')[0] if 'T' in hash_data['timestamp'] else hash_data[
                'timestamp']

            # Formatear fuente de manera profesional
            if hash_data['source_type'] == 'text':
                # Usar identificador profesional en lugar de mostrar información del texto
                source_display = f"Data Entry #{hash_data['id']}"

                # Si es un algoritmo de contraseña, usar terminología específica
                if hash_data['algorithm'] in ['bcrypt', 'Argon2']:
                    source_display = f"Credential Entry #{hash_data['id']}"
            else:
                # Para archivos, solo mostrar el nombre
                source_display = hash_data['source_name'] or f"File Entry #{hash_data['id']}"

            self.history_tree.insert("", tk.END, values=(
                hash_data['id'],
                hash_data['source_type'],
                source_display,
                hash_data['hash_value'],
                hash_data['algorithm'],
                size,
                timestamp
            ))

    def on_select(self, event):
        """Muestra detalles cuando se selecciona un elemento"""
        selected_items = self.history_tree.selection()
        if not selected_items:
            return

        item = selected_items[0]
        item_data = self.history_tree.item(item, "values")

        if not item_data:
            return

        hash_id = item_data[0]

        # Obtener detalles completos
        hash_details = self.db.get_hash_by_id(hash_id)

        if hash_details:
            details = f"ID: {hash_details['id']}\n"
            details += f"Algoritmo: {hash_details['algorithm']}\n"
            details += f"Tipo: {hash_details['source_type']}\n"

            # Mostrar información profesional sobre la fuente
            if hash_details['source_type'] == 'text':
                if hash_details['algorithm'] in ['bcrypt', 'Argon2']:
                    details += f"Fuente: Credential Entry #{hash_details['id']}\n"
                    details += f"Tipo de dato: Contraseña/Credencial\n"
                else:
                    details += f"Fuente: Data Entry #{hash_details['id']}\n"
                    details += f"Tipo de dato: Texto genérico\n"
            else:
                details += f"Fuente: {hash_details['source_name']}\n"
                details += f"Tipo de dato: Archivo\n"
                if hash_details.get('original_path') and not self.secure_mode:
                    details += f"Ruta original: {hash_details['original_path']}\n"

            size_value = hash_details.get('source_size')
            if size_value is None:
                size_value = 0
            details += f"Tamaño: {self.format_size(size_value)}\n"
            details += f"Fecha: {hash_details['timestamp']}\n"

            if hash_details.get('created_by'):
                details += f"Creado por: {hash_details['created_by']}\n"

            if hash_details.get('integrity_verified') is not None:
                details += f"Integridad: {'Verificada ✓' if hash_details['integrity_verified'] else 'No verificada ⚠'}\n"

            # Mostrar información de sal si existe
            if hash_details['algorithm'] in ['bcrypt', 'Argon2']:
                if hash_details['algorithm'] == 'bcrypt':
                    # Para bcrypt, extraer la sal del hash mismo
                    try:
                        parts = hash_details['hash_value'].split('$')
                        if len(parts) >= 4:
                            salt_part = parts[3][:22]  # Los primeros 22 caracteres después del costo
                            details += f"\nSal utilizada: ${parts[1]}${parts[2]}${salt_part}\n"
                            details += f"Nota: bcrypt incluye la sal en el hash mismo\n"
                    except:
                        details += f"\nNota: Este algoritmo usa sal integrada\n"
                elif hash_details.get('salt'):
                    details += f"\nSal utilizada: {hash_details['salt']}\n"
                    details += f"Nota: Este algoritmo usa sal para mayor seguridad\n"

            if not self.secure_mode:
                details += f"\nHash completo:\n{hash_details['hash_value']}\n"

            if hash_details.get('metadata'):
                details += f"\nMetadatos: {json.dumps(hash_details['metadata'], indent=2)}\n"

            self.details_text.delete("1.0", tk.END)
            self.details_text.insert(tk.END, details)

    def copy_selected_hash(self):
        """Copia el hash seleccionado al portapapeles"""
        selected_items = self.history_tree.selection()
        if not selected_items:
            messagebox.showinfo("Información", "Por favor seleccione un hash para copiar.")
            return

        item = selected_items[0]
        item_data = self.history_tree.item(item, "values")

        if not item_data or len(item_data) < 4:
            return

        hash_value = item_data[3]  # Columna del hash

        if "..." in hash_value and self.secure_mode:
            messagebox.showwarning("Advertencia",
                                   "No se puede copiar el hash completo en modo seguro.")
            return

        self.parent.clipboard_clear()
        self.parent.clipboard_append(hash_value)
        self.status_var.set("Hash copiado al portapapeles")

    def format_size(self, size):
        """Formato para tamaño de archivo"""
        if size == 0:
            return "0 B"

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"