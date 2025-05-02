import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
from src.hash_utils import calculate_hash_file, calculate_hash_string
from src.db_utils import HashDatabase


class HashConverterTab:
    def __init__(self, parent, algorithms, status_var):
        self.parent = parent
        self.algorithms = algorithms
        self.status_var = status_var
        self.db = HashDatabase()

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Título principal
        ttk.Label(frame, text="Generar Hash de Texto o Archivo:", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))

        # Frame para selección del tipo de entrada
        input_type_frame = ttk.Frame(frame)
        input_type_frame.pack(fill=tk.X, pady=5)

        self.input_type_var = tk.StringVar(value="text")
        text_radio = ttk.Radiobutton(input_type_frame, text="Texto",
                                     variable=self.input_type_var, value="text",
                                     command=self.toggle_input_mode)
        text_radio.pack(side=tk.LEFT, padx=10)

        file_radio = ttk.Radiobutton(input_type_frame, text="Archivo",
                                     variable=self.input_type_var, value="file",
                                     command=self.toggle_input_mode)
        file_radio.pack(side=tk.LEFT, padx=10)

        # Frame contenedor para las entradas (texto/archivo)
        self.input_container = ttk.Frame(frame)
        self.input_container.pack(fill=tk.BOTH, expand=True, pady=10)

        # Frame para entrada de texto
        self.text_frame = ttk.Frame(self.input_container)
        self.input_text = scrolledtext.ScrolledText(self.text_frame, height=8, width=50, wrap=tk.WORD)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # Frame para selección de archivo
        self.file_frame = ttk.Frame(self.input_container)

        file_select_frame = ttk.Frame(self.file_frame)
        file_select_frame.pack(fill=tk.X, pady=5)

        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_select_frame, textvariable=self.file_path_var, width=50)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        browse_button = ttk.Button(file_select_frame, text="Examinar", command=self.browse_file)
        browse_button.pack(side=tk.RIGHT)

        # Información del archivo
        self.file_info_frame = ttk.LabelFrame(self.file_frame, text="Información del Archivo")
        self.file_info_frame.pack(fill=tk.X, pady=10)

        self.file_info = scrolledtext.ScrolledText(self.file_info_frame, height=5, width=50, wrap=tk.WORD)
        self.file_info.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Opciones de algoritmo
        algorithm_frame = ttk.Frame(frame)
        algorithm_frame.pack(fill=tk.X, pady=10)

        ttk.Label(algorithm_frame, text="Algoritmo:").pack(side=tk.LEFT, padx=(0, 10))

        # Lista actualizada de algoritmos con los nuevos
        self.algorithm_var = tk.StringVar(value="SHA-256")
        self.algorithm_dropdown = ttk.Combobox(algorithm_frame, textvariable=self.algorithm_var,
                                               values=self.algorithms, state="readonly", width=25)
        self.algorithm_dropdown.pack(side=tk.LEFT)

        # Botones
        buttons_frame = ttk.Frame(frame)
        buttons_frame.pack(fill=tk.X, pady=5)

        # Botón guardar en historial
        save_button = ttk.Button(buttons_frame, text="Guardar en Historial",
                                 command=self.save_to_history)
        save_button.pack(side=tk.LEFT, padx=5)

        # Botón de generar hash
        generate_button = ttk.Button(buttons_frame, text="Generar Hash",
                                     command=self.generate_hash)
        generate_button.pack(side=tk.RIGHT, padx=5)

        # Botón de copiar hash
        copy_button = ttk.Button(buttons_frame, text="Copiar Hash",
                                 command=lambda: self.copy_to_clipboard(self.hash_result.get("1.0", tk.END).strip()))
        copy_button.pack(side=tk.RIGHT, padx=5)

        # Resultados
        result_frame = ttk.LabelFrame(frame, text="Resultado del Hash")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.hash_result = scrolledtext.ScrolledText(result_frame, height=3, width=50, wrap=tk.WORD)
        self.hash_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Iniciar con modo texto
        self.toggle_input_mode()

    def toggle_input_mode(self):
        """Alterna entre modo texto y archivo"""
        # Ocultar todos los frames
        for widget in self.input_container.winfo_children():
            widget.pack_forget()

        if self.input_type_var.get() == "text":
            self.text_frame.pack(fill=tk.BOTH, expand=True)
        else:
            self.file_frame.pack(fill=tk.BOTH, expand=True)

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_path_var.set(filepath)
            self.display_file_info(filepath)

    def display_file_info(self, filepath):
        try:
            file_size = os.path.getsize(filepath)
            file_name = os.path.basename(filepath)
            modified_time = os.path.getmtime(filepath)

            info = f"Nombre: {file_name}\n"
            info += f"Tamaño: {self.format_size(file_size)}\n"
            info += f"Última modificación: {time.ctime(modified_time)}"

            self.file_info.delete("1.0", tk.END)
            self.file_info.insert(tk.END, info)
        except Exception as e:
            self.file_info.delete("1.0", tk.END)
            self.file_info.insert(tk.END, f"Error al obtener información: {str(e)}")

    def format_size(self, size):
        """Formato para tamaño de archivo"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

    def generate_hash(self):
        algorithm = self.algorithm_var.get()

        try:
            if self.input_type_var.get() == "text":
                # Generar hash de texto
                text = self.input_text.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showwarning("Advertencia", "Por favor ingrese texto para generar el hash.")
                    return

                self.status_var.set(f"Calculando hash {algorithm} para el texto...")
                result = calculate_hash_string(text, algorithm)

            else:
                # Generar hash de archivo
                filepath = self.file_path_var.get()
                if not filepath or not os.path.isfile(filepath):
                    messagebox.showwarning("Advertencia", "Por favor seleccione un archivo válido.")
                    return

                self.status_var.set(f"Calculando hash {algorithm} para el archivo...")
                result = calculate_hash_file(filepath, algorithm)

            self.hash_result.delete("1.0", tk.END)
            self.hash_result.insert(tk.END, result)
            self.status_var.set(f"Hash {algorithm} generado con éxito")

        except Exception as e:
            messagebox.showerror("Error", f"Error al calcular el hash: {str(e)}")
            self.status_var.set("Error al calcular el hash")

    def copy_to_clipboard(self, text):
        self.parent.clipboard_clear()
        self.parent.clipboard_append(text)
        self.status_var.set("Hash copiado al portapapeles")

    def save_to_history(self):
        hash_value = self.hash_result.get("1.0", tk.END).strip()
        algorithm = self.algorithm_var.get()

        if not hash_value:
            messagebox.showwarning("Advertencia", "Por favor genere un hash primero.")
            return

        try:
            if self.input_type_var.get() == "text":
                # Guardar hash de texto
                text = self.input_text.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showwarning("Advertencia", "Por favor ingrese texto para guardar.")
                    return

                source_name = text[:20] + "..." if len(text) > 20 else text
                self.db.save_hash(hash_value, algorithm, 'text', source_name)

            else:
                # Guardar hash de archivo
                filepath = self.file_path_var.get()
                if not filepath or not os.path.isfile(filepath):
                    messagebox.showwarning("Advertencia", "Por favor seleccione un archivo válido.")
                    return

                file_name = os.path.basename(filepath)
                self.db.save_hash(hash_value, algorithm, 'file', file_name)

            self.status_var.set("Hash guardado en el historial")
            messagebox.showinfo("Éxito", "El hash ha sido guardado en el historial.")

        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar en la base de datos: {str(e)}")
            self.status_var.set("Error al guardar en la base de datos")