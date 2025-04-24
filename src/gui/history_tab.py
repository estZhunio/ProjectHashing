import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
from src.db_utils import HashDatabase


class HistoryTab:
    def __init__(self, parent, algorithms, status_var):
        self.parent = parent
        self.algorithms = algorithms
        self.status_var = status_var
        self.db = HashDatabase()

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Historial de Hashing", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))

        # Pestañas para texto y archivos
        history_notebook = ttk.Notebook(frame)
        history_notebook.pack(fill=tk.BOTH, expand=True)

        # Pestaña de historial de texto
        text_history_tab = ttk.Frame(history_notebook)
        history_notebook.add(text_history_tab, text="Hashes de Texto")

        # Pestaña de historial de archivos
        file_history_tab = ttk.Frame(history_notebook)
        history_notebook.add(file_history_tab, text="Hashes de Archivos")

        # Configurar las pestañas
        self.setup_text_history_tab(text_history_tab)
        self.setup_file_history_tab(file_history_tab)

        # Botón de actualización
        refresh_button = ttk.Button(frame, text="Actualizar Historial", command=self.refresh_history)
        refresh_button.pack(pady=10)

    def setup_text_history_tab(self, parent):
        # Crear treeview para mostrar historial de texto
        columns = ("ID", "Descripción", "Hash", "Algoritmo", "Fecha")
        self.text_tree = ttk.Treeview(parent, columns=columns, show="headings", height=15)

        # Configurar columnas
        self.text_tree.heading("ID", text="ID")
        self.text_tree.heading("Descripción", text="Descripción")
        self.text_tree.heading("Hash", text="Hash")
        self.text_tree.heading("Algoritmo", text="Algoritmo")
        self.text_tree.heading("Fecha", text="Fecha")

        self.text_tree.column("ID", width=40, anchor=tk.CENTER)
        self.text_tree.column("Descripción", width=150)
        self.text_tree.column("Hash", width=300)
        self.text_tree.column("Algoritmo", width=80, anchor=tk.CENTER)
        self.text_tree.column("Fecha", width=150)

        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.text_tree.yview)
        self.text_tree.configure(yscroll=scrollbar.set)

        # Empaquetar
        self.text_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Botones para acciones
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=5)

        copy_hash_btn = ttk.Button(button_frame, text="Copiar Hash Seleccionado",
                                   command=self.copy_selected_hash)
        copy_hash_btn.pack(side=tk.LEFT, padx=5)

        # Cargar datos iniciales
        self.load_text_history()

    def setup_file_history_tab(self, parent):
        # Similar a la pestaña de texto pero para archivos
        columns = ("ID", "Archivo", "Hash", "Algoritmo", "Fecha")
        self.file_tree = ttk.Treeview(parent, columns=columns, show="headings", height=15)

        # Configurar columnas
        self.file_tree.heading("ID", text="ID")
        self.file_tree.heading("Archivo", text="Archivo")
        self.file_tree.heading("Hash", text="Hash")
        self.file_tree.heading("Algoritmo", text="Algoritmo")
        self.file_tree.heading("Fecha", text="Fecha")

        self.file_tree.column("ID", width=40, anchor=tk.CENTER)
        self.file_tree.column("Archivo", width=150)
        self.file_tree.column("Hash", width=300)
        self.file_tree.column("Algoritmo", width=80, anchor=tk.CENTER)
        self.file_tree.column("Fecha", width=150)

        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscroll=scrollbar.set)

        # Empaquetar
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Botones para acciones
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=5)

        copy_hash_btn = ttk.Button(button_frame, text="Copiar Hash Seleccionado",
                                   command=self.copy_selected_file_hash)
        copy_hash_btn.pack(side=tk.LEFT, padx=5)

        # Cargar datos iniciales
        self.load_file_history()

    def load_text_history(self):
        # Limpiar árbol existente
        for item in self.text_tree.get_children():
            self.text_tree.delete(item)

        # Cargar datos de la base de datos
        text_hashes = self.db.get_recent_hashes(50, 'text')

        for hash_data in text_hashes:
            id, hash_value, algorithm, source_type, source_name, timestamp = hash_data
            self.text_tree.insert("", tk.END, values=(id, source_name, hash_value, algorithm, timestamp))

    def load_file_history(self):
        # Limpiar árbol existente
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)

        # Cargar datos de la base de datos
        file_hashes = self.db.get_recent_hashes(50, 'file')

        for hash_data in file_hashes:
            id, hash_value, algorithm, source_type, source_name, timestamp = hash_data
            self.file_tree.insert("", tk.END, values=(id, source_name, hash_value, algorithm, timestamp))

    def copy_selected_hash(self):
        selected_items = self.text_tree.selection()
        if not selected_items:
            messagebox.showinfo("Información", "Por favor seleccione un hash para copiar.")
            return

        item = selected_items[0]
        item_data = self.text_tree.item(item, "values")

        if not item_data or len(item_data) < 3:
            return

        hash_value = item_data[2]  # La columna del hash

        self.parent.clipboard_clear()
        self.parent.clipboard_append(hash_value)
        self.status_var.set("Hash copiado al portapapeles")

    def copy_selected_file_hash(self):
        selected_items = self.file_tree.selection()
        if not selected_items:
            messagebox.showinfo("Información", "Por favor seleccione un hash para copiar.")
            return

        item = selected_items[0]
        item_data = self.file_tree.item(item, "values")

        if not item_data or len(item_data) < 3:
            return

        hash_value = item_data[2]  # La columna del hash

        self.parent.clipboard_clear()
        self.parent.clipboard_append(hash_value)
        self.status_var.set("Hash copiado al portapapeles")

    def refresh_history(self):
        self.load_text_history()
        self.load_file_history()
        self.status_var.set("Historial actualizado")