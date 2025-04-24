import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from src.hash_utils import calculate_hash_string
from src.db_utils import HashDatabase


class TextHashTab:
    def __init__(self, parent, algorithms, status_var):
        self.parent = parent
        self.algorithms = algorithms
        self.status_var = status_var
        self.db = HashDatabase()  # Inicializar la base de datos

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Instrucciones
        ttk.Label(frame, text="Ingrese texto para generar su hash:", style='Header.TLabel').pack(anchor=tk.W,
                                                                                                 pady=(0, 5))

        # Campo de entrada de texto
        text_frame = ttk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.input_text = scrolledtext.ScrolledText(text_frame, height=5, width=50, wrap=tk.WORD)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # Opciones de algoritmo
        algorithm_frame = ttk.Frame(frame)
        algorithm_frame.pack(fill=tk.X, pady=10)

        ttk.Label(algorithm_frame, text="Algoritmo:").pack(side=tk.LEFT, padx=(0, 10))

        self.algorithm_var = tk.StringVar(value=self.algorithms[0])
        algorithm_dropdown = ttk.Combobox(algorithm_frame, textvariable=self.algorithm_var,
                                          values=self.algorithms, state="readonly", width=15)
        algorithm_dropdown.pack(side=tk.LEFT)

        # Botones
        buttons_frame = ttk.Frame(frame)
        buttons_frame.pack(fill=tk.X, pady=5)

        # Botón guardar en historial (NUEVO)
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

    def generate_hash(self):
        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Advertencia", "Por favor ingrese texto para generar el hash.")
            return

        algorithm = self.algorithm_var.get()
        result = calculate_hash_string(text, algorithm)

        self.hash_result.delete("1.0", tk.END)
        self.hash_result.insert(tk.END, result)
        self.status_var.set(f"Hash {algorithm} generado con éxito")

    def copy_to_clipboard(self, text):
        self.parent.clipboard_clear()
        self.parent.clipboard_append(text)
        self.status_var.set("Hash copiado al portapapeles")

    # Funcion para guardar en historial

    def save_to_history(self):
        text = self.input_text.get("1.0", tk.END).strip()
        hash_value = self.hash_result.get("1.0", tk.END).strip()
        algorithm = self.algorithm_var.get()

        if not text:
            messagebox.showwarning("Advertencia", "Por favor ingrese texto para guardar.")
            return

        if not hash_value:
            messagebox.showwarning("Advertencia", "Por favor genere un hash primero.")
            return

        try:
            # Guardar solo el hash en la base de datos
            source_name = text[:20] + "..." if len(text) > 20 else text  # Solo para referencia
            self.db.save_hash(hash_value, algorithm, 'text', source_name)
            self.status_var.set("Hash guardado en el historial")
            messagebox.showinfo("Éxito", "El hash ha sido guardado en el historial.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar en la base de datos: {str(e)}")
            self.status_var.set("Error al guardar en la base de datos")