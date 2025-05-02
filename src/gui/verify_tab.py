import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from src.hash_utils import calculate_hash_string, calculate_hash_file
from src.verificacion import verificar_integridad_texto, verificar_integridad_archivo
from src.db_utils import HashDatabase


class VerifyTab:
    def __init__(self, parent, algorithms, status_var):
        self.parent = parent
        self.algorithms = algorithms
        self.status_var = status_var
        self.db = HashDatabase()

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Título y descripción educativa
        ttk.Label(frame, text="Verificación de Integridad", style='Header.TLabel').pack(anchor=tk.W)
        ttk.Label(frame, text="Comprueba si un archivo o texto ha sido modificado comparando su hash",
                  foreground='gray').pack(anchor=tk.W, pady=(0, 10))

        # Opciones de verificación
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill=tk.X, pady=5)

        self.verify_option = tk.StringVar(value="text")
        ttk.Radiobutton(options_frame, text="Verificar Texto", variable=self.verify_option, value="text",
                        command=self.toggle_verify_input).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(options_frame, text="Verificar Archivo", variable=self.verify_option, value="file",
                        command=self.toggle_verify_input).pack(side=tk.LEFT)

        # Opciones de algoritmo
        algorithm_frame = ttk.Frame(frame)
        algorithm_frame.pack(fill=tk.X, pady=10)

        ttk.Label(algorithm_frame, text="Algoritmo:").pack(side=tk.LEFT, padx=(0, 10))

        self.algorithm_var = tk.StringVar(value=self.algorithms[0])
        self.algorithm_dropdown = ttk.Combobox(algorithm_frame, textvariable=self.algorithm_var,
                                               values=self.algorithms, state="readonly", width=15)
        self.algorithm_dropdown.pack(side=tk.LEFT)

        # Vincular evento de cambio para limpiar hash si cambia el algoritmo
        self.algorithm_trace_id = self.algorithm_var.trace('w', self.on_algorithm_change)

        # Frame principal dividido en dos columnas
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Columna izquierda - Original
        left_frame = ttk.LabelFrame(main_frame, text="Entrada Original", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Para texto
        self.verify_text_frame = ttk.Frame(left_frame)
        self.verify_original_text = scrolledtext.ScrolledText(self.verify_text_frame, height=8, width=40, wrap=tk.WORD)
        self.verify_original_text.pack(fill=tk.BOTH, expand=True)

        # Para archivo
        self.verify_file_frame = ttk.Frame(left_frame)

        self.verify_original_file_var = tk.StringVar()
        file_entry = ttk.Entry(self.verify_file_frame, textvariable=self.verify_original_file_var)
        file_entry.pack(fill=tk.X, pady=(0, 5))

        browse_button = ttk.Button(self.verify_file_frame, text="Examinar",
                                   command=self.browse_verify_file)
        browse_button.pack(fill=tk.X)

        # Columna derecha - Hash a verificar
        right_frame = ttk.LabelFrame(main_frame, text="Hash de Referencia", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # Campo de hash
        self.verify_hash = ttk.Entry(right_frame, width=40)
        self.verify_hash.pack(fill=tk.X, pady=(0, 10))

        # Frame para botones de carga
        load_frame = ttk.Frame(right_frame)
        load_frame.pack(fill=tk.X, pady=5)

        # Botón para cargar desde historial
        load_button = ttk.Button(load_frame, text="Cargar desde Historial",
                                 command=self.load_from_history)
        load_button.pack(fill=tk.X)

        # Botones de acción
        action_frame = ttk.Frame(frame)
        action_frame.pack(fill=tk.X, pady=10)

        verify_button = ttk.Button(action_frame, text="Verificar Integridad", command=self.verify_hash_match)
        verify_button.pack(side=tk.LEFT, padx=5)

        clear_button = ttk.Button(action_frame, text="Limpiar Todo", command=self.clear_all)
        clear_button.pack(side=tk.RIGHT, padx=5)

        # Resultados con visual mejorado
        result_frame = ttk.LabelFrame(frame, text="Resultado de la Verificación")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.verify_result = scrolledtext.ScrolledText(result_frame, height=6, width=50)
        self.verify_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Variable para controlar si se cargó desde historial
        self.loaded_from_history = False

        # Inicialmente mostrar la opción de texto
        self.toggle_verify_input()

    def on_algorithm_change(self, *args):
        """Limpia el hash si se cambia el algoritmo después de cargar desde historial"""
        if self.loaded_from_history:
            self.verify_hash.delete(0, tk.END)
            self.loaded_from_history = False
            self.status_var.set("Hash limpiado - Algoritmo cambiado")

    def toggle_verify_input(self):
        if self.verify_option.get() == "text":
            self.verify_file_frame.pack_forget()
            self.verify_text_frame.pack(fill=tk.BOTH, expand=True)
        else:
            self.verify_text_frame.pack_forget()
            self.verify_file_frame.pack(fill=tk.BOTH, expand=True)

    def browse_verify_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.verify_original_file_var.set(filepath)

    def load_from_history(self):
        """Carga un hash desde el historial"""
        # Ventana de diálogo para seleccionar hash
        dialog = tk.Toplevel(self.parent)
        dialog.title("Seleccionar Hash del Historial")
        dialog.geometry("600x400")
        dialog.transient(self.parent)  # Hacer la ventana modal
        dialog.grab_set()  # Evitar interacción con la ventana principal

        # Lista de hashes
        columns = ("ID", "Fuente", "Algoritmo", "Hash")
        tree = ttk.Treeview(dialog, columns=columns, show="headings", height=10)

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100 if col == "ID" else 150)

        # Cargar datos
        hashes = self.db.get_recent_hashes(limit=50)
        for hash_data in hashes:
            source_display = f"Data Entry #{hash_data['id']}" if hash_data['source_type'] == 'text' else hash_data[
                'source_name']
            tree.insert("", tk.END, values=(
                hash_data['id'],
                source_display,
                hash_data['algorithm'],
                hash_data['hash_value'][:20] + "..." if len(hash_data['hash_value']) > 20 else hash_data['hash_value']
            ))

        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        def select_hash():
            selected = tree.selection()
            if selected:
                item = tree.item(selected[0])
                values = item['values']
                # Obtener el hash completo
                try:
                    hash_id = int(values[0])  # Convertir ID a entero
                    full_hash = self.db.get_hash_by_id(hash_id)
                    if full_hash:
                        self.verify_hash.delete(0, tk.END)
                        self.verify_hash.insert(0, full_hash['hash_value'])
                        self.algorithm_var.set(full_hash['algorithm'])
                        self.loaded_from_history = True  # Marcar que se cargó desde historial
                except (ValueError, TypeError) as e:
                    messagebox.showerror("Error", f"Error al obtener el hash: {str(e)}")
                dialog.destroy()

        select_button = ttk.Button(dialog, text="Seleccionar", command=select_hash)
        select_button.pack(pady=10)

    def calculate_verify_hash(self):
        algorithm = self.algorithm_var.get()

        try:
            if self.verify_option.get() == "text":
                text = self.verify_original_text.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showwarning("Advertencia", "Por favor ingrese texto para calcular el hash.")
                    return
                result = calculate_hash_string(text, algorithm)
            else:
                filepath = self.verify_original_file_var.get()
                if not filepath or not os.path.isfile(filepath):
                    messagebox.showwarning("Advertencia", "Por favor seleccione un archivo válido.")
                    return
                result = calculate_hash_file(filepath, algorithm)

            self.verify_hash.delete(0, tk.END)
            self.verify_hash.insert(0, result)
            self.status_var.set(f"Hash {algorithm} calculado con éxito")
        except Exception as e:
            messagebox.showerror("Error", f"Error al calcular el hash: {str(e)}")
            self.status_var.set("Error al calcular el hash")

    def verify_hash_match(self):
        algorithm = self.algorithm_var.get()
        hash_to_verify = self.verify_hash.get().strip()  # NO usar .lower()

        if not hash_to_verify:
            messagebox.showwarning("Advertencia", "Por favor ingrese un hash para verificar.")
            return

        try:
            if self.verify_option.get() == "text":
                text = self.verify_original_text.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showwarning("Advertencia", "Por favor ingrese texto para verificar.")
                    return
                es_valido, calculated_hash = verificar_integridad_texto(text, hash_to_verify, algorithm)
            else:
                filepath = self.verify_original_file_var.get()
                if not filepath or not os.path.isfile(filepath):
                    messagebox.showwarning("Advertencia", "Por favor seleccione un archivo válido.")
                    return
                es_valido, calculated_hash = verificar_integridad_archivo(filepath, hash_to_verify, algorithm)

            self.verify_result.delete("1.0", tk.END)

            if es_valido:
                self.verify_result.insert(tk.END, "VERIFICACIÓN EXITOSA\n\n")
                self.verify_result.insert(tk.END, "Los hashes coinciden. La integridad ha sido verificada.\n\n")
                self.verify_result.insert(tk.END, "Esto significa que los datos NO han sido modificados.")
                self.verify_result.tag_configure("green", foreground="green", font=("Arial", 12, "bold"))
                self.verify_result.tag_add("green", "1.0", "1.end")
                self.status_var.set("Verificación exitosa - Integridad confirmada")
            else:
                self.verify_result.insert(tk.END, "VERIFICACIÓN FALLIDA\n\n")
                self.verify_result.insert(tk.END, "Los hashes NO coinciden.\n\n")
                self.verify_result.insert(tk.END, "ADVERTENCIA: Los datos han sido modificados o corrompidos.")
                self.verify_result.tag_configure("red", foreground="red", font=("Arial", 12, "bold"))
                self.verify_result.tag_add("red", "1.0", "1.end")
                self.status_var.set("Verificación fallida - Integridad comprometida")

                # Para bcrypt y Argon2, mostrar mensaje especial
                if algorithm in ["bcrypt", "Argon2"]:
                    self.verify_result.insert(tk.END, "\n\nNota: Con bcrypt y Argon2, cada hash usa una sal única. ")
                    self.verify_result.insert(tk.END,
                                              "Si la verificación falla, asegúrese de usar el hash exacto guardado.")
                else:
                    # Mostrar comparación detallada solo para otros algoritmos
                    self.verify_result.insert(tk.END, f"\n\nComparación de hashes:\n")
                    self.verify_result.insert(tk.END, f"Calculado: {calculated_hash}\n")
                    self.verify_result.insert(tk.END, f"Esperado:  {hash_to_verify}")

                    # Resaltar diferencias
                    self.verify_result.tag_configure("diff", background="yellow")

        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar el hash: {str(e)}")
            self.status_var.set("Error al verificar el hash")

    def clear_all(self):
        """Limpia todos los campos"""
        self.verify_original_text.delete("1.0", tk.END)
        self.verify_original_file_var.set("")
        self.verify_hash.delete(0, tk.END)
        self.verify_result.delete("1.0", tk.END)
        self.status_var.set("Campos limpiados")