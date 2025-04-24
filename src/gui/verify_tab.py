import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from src.hash_utils import calculate_hash_string, calculate_hash_file
from src.verificacion import verificar_integridad_texto, verificar_integridad_archivo


class VerifyTab:
    def __init__(self, parent, algorithms, status_var):
        self.parent = parent
        self.algorithms = algorithms
        self.status_var = status_var

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Instrucciones
        ttk.Label(frame, text="Verificación de Integridad", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))

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
        algorithm_dropdown = ttk.Combobox(algorithm_frame, textvariable=self.algorithm_var,
                                          values=self.algorithms, state="readonly", width=15)
        algorithm_dropdown.pack(side=tk.LEFT)

        # Entrada original
        original_frame = ttk.LabelFrame(frame, text="Original")
        original_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Para texto
        self.verify_text_frame = ttk.Frame(original_frame)
        self.verify_text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.verify_original_text = scrolledtext.ScrolledText(self.verify_text_frame, height=3, width=50, wrap=tk.WORD)
        self.verify_original_text.pack(fill=tk.BOTH, expand=True)

        # Para archivo
        self.verify_file_frame = ttk.Frame(original_frame)

        self.verify_original_file_var = tk.StringVar()
        file_entry = ttk.Entry(self.verify_file_frame, textvariable=self.verify_original_file_var, width=50)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        browse_button = ttk.Button(self.verify_file_frame, text="Examinar",
                                   command=self.browse_verify_file)
        browse_button.pack(side=tk.RIGHT)

        # Hash a verificar
        verify_hash_frame = ttk.LabelFrame(frame, text="Hash a Verificar")
        verify_hash_frame.pack(fill=tk.X, pady=10)

        self.verify_hash = ttk.Entry(verify_hash_frame, width=100)
        self.verify_hash.pack(fill=tk.X, padx=5, pady=5)

        # Botones de acción
        action_frame = ttk.Frame(frame)
        action_frame.pack(fill=tk.X, pady=10)

        calculate_button = ttk.Button(action_frame, text="Calcular Hash", command=self.calculate_verify_hash)
        calculate_button.pack(side=tk.LEFT, padx=5)

        verify_button = ttk.Button(action_frame, text="Verificar Hash", command=self.verify_hash_match)
        verify_button.pack(side=tk.LEFT, padx=5)

        # Resultados
        result_frame = ttk.LabelFrame(frame, text="Resultado")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.verify_result = scrolledtext.ScrolledText(result_frame, height=3, width=50)
        self.verify_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Inicialmente mostrar la opción de texto
        self.toggle_verify_input()

    def toggle_verify_input(self):
        if self.verify_option.get() == "text":
            self.verify_file_frame.pack_forget()
            self.verify_text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            self.verify_text_frame.pack_forget()
            self.verify_file_frame.pack(fill=tk.X, padx=5, pady=5)

    def browse_verify_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.verify_original_file_var.set(filepath)

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
        hash_to_verify = self.verify_hash.get().strip().lower()

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
                self.verify_result.insert(tk.END,
                                          "✅ VERIFICACIÓN EXITOSA\n\nLos hashes coinciden. La integridad ha sido verificada.")
                self.verify_result.tag_configure("green", foreground="green")
                self.verify_result.tag_add("green", "1.0", tk.END)
                self.status_var.set("Verificación exitosa")
            else:
                self.verify_result.insert(tk.END,
                                          "❌ VERIFICACIÓN FALLIDA\n\nLos hashes no coinciden. La integridad no pudo ser verificada.")
                self.verify_result.tag_configure("red", foreground="red")
                self.verify_result.tag_add("red", "1.0", tk.END)
                self.status_var.set("Verificación fallida")

                # Mostrar comparación
                self.verify_result.insert(tk.END,
                                          f"\n\nHash calculado:\n{calculated_hash}\n\nHash proporcionado:\n{hash_to_verify}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar el hash: {str(e)}")
            self.status_var.set("Error al verificar el hash")