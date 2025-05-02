import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from src.digital_signature import DigitalSignatureManager


class DigitalSignatureTab:
    def __init__(self, parent, algorithms, status_var):
        self.parent = parent
        self.algorithms = algorithms
        self.status_var = status_var
        self.signature_manager = DigitalSignatureManager()

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Título
        ttk.Label(frame, text="Firmas Digitales", style='Header.TLabel').pack(anchor=tk.W)
        ttk.Label(frame, text="Firma y verifica archivos usando criptografía asimétrica",
                  foreground='gray').pack(anchor=tk.W, pady=(0, 10))

        # Frame principal con dos secciones
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Sección izquierda - Firmar
        sign_frame = ttk.LabelFrame(main_frame, text="Firmar Documento", padding=10)
        sign_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Sección derecha - Verificar
        verify_frame = ttk.LabelFrame(main_frame, text="Verificar Firma", padding=10)
        verify_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        self.setup_sign_section(sign_frame)
        self.setup_verify_section(verify_frame)

        # Sección de claves
        keys_frame = ttk.LabelFrame(frame, text="Gestión de Claves", padding=10)
        keys_frame.pack(fill=tk.X, pady=10)
        self.setup_keys_section(keys_frame)

    def setup_sign_section(self, parent):
        # Entrada de texto
        ttk.Label(parent, text="Texto a firmar:").pack(anchor=tk.W)
        self.sign_text = scrolledtext.ScrolledText(parent, height=6, width=40, wrap=tk.WORD)
        self.sign_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Selección de algoritmo
        algorithm_frame = ttk.Frame(parent)
        algorithm_frame.pack(fill=tk.X, pady=5)

        ttk.Label(algorithm_frame, text="Algoritmo:").pack(side=tk.LEFT)
        self.sign_algorithm_var = tk.StringVar(value="SHA-256")
        hash_algorithms = ["SHA-256", "SHA-512", "SHA-3"]
        algorithm_dropdown = ttk.Combobox(algorithm_frame, textvariable=self.sign_algorithm_var,
                                          values=hash_algorithms, state="readonly", width=15)
        algorithm_dropdown.pack(side=tk.LEFT, padx=5)

        # Botón de firmar
        sign_btn = ttk.Button(parent, text="Firmar", command=self.sign_data)
        sign_btn.pack(fill=tk.X, pady=5)

        # Resultado
        ttk.Label(parent, text="Firma Digital:").pack(anchor=tk.W)
        self.sign_result = scrolledtext.ScrolledText(parent, height=4, width=40, wrap=tk.WORD)
        self.sign_result.pack(fill=tk.BOTH, expand=True, pady=5)

        # Botones de acción
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=5)

        copy_btn = ttk.Button(action_frame, text="Copiar Firma",
                              command=lambda: self.copy_to_clipboard(self.sign_result.get("1.0", tk.END).strip()))
        copy_btn.pack(side=tk.LEFT, padx=5)

        save_btn = ttk.Button(action_frame, text="Guardar Firma", command=self.save_signature)
        save_btn.pack(side=tk.LEFT, padx=5)

    def setup_verify_section(self, parent):
        # Texto a verificar
        ttk.Label(parent, text="Texto original:").pack(anchor=tk.W)
        self.verify_text = scrolledtext.ScrolledText(parent, height=6, width=40, wrap=tk.WORD)
        self.verify_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Firma
        ttk.Label(parent, text="Firma Digital:").pack(anchor=tk.W)
        self.verify_signature = scrolledtext.ScrolledText(parent, height=4, width=40, wrap=tk.WORD)
        self.verify_signature.pack(fill=tk.BOTH, expand=True, pady=5)

        load_btn = ttk.Button(parent, text="Cargar Firma", command=self.load_signature)
        load_btn.pack(fill=tk.X, pady=5)

        # Botón de verificar
        verify_btn = ttk.Button(parent, text="Verificar Firma", command=self.verify_signature_func)
        verify_btn.pack(fill=tk.X, pady=5)

        # Resultado
        ttk.Label(parent, text="Resultado:").pack(anchor=tk.W)
        self.verify_result = scrolledtext.ScrolledText(parent, height=4, width=40, wrap=tk.WORD)
        self.verify_result.pack(fill=tk.BOTH, expand=True, pady=5)

    def setup_keys_section(self, parent):
        keys_frame = ttk.Frame(parent)
        keys_frame.pack(fill=tk.X)

        generate_btn = ttk.Button(keys_frame, text="Generar Par de Claves",
                                  command=self.generate_keys)
        generate_btn.pack(side=tk.LEFT, padx=5)

        save_keys_btn = ttk.Button(keys_frame, text="Guardar Claves",
                                   command=self.save_keys)
        save_keys_btn.pack(side=tk.LEFT, padx=5)

        load_keys_btn = ttk.Button(keys_frame, text="Cargar Claves",
                                   command=self.load_keys)
        load_keys_btn.pack(side=tk.LEFT, padx=5)

        # Estado
        self.key_status = ttk.Label(parent, text="Estado: Sin claves cargadas", foreground='red')
        self.key_status.pack(pady=10)

    def sign_data(self):
        try:
            data = self.sign_text.get("1.0", tk.END).strip()
            if not data:
                messagebox.showwarning("Advertencia", "Por favor ingrese texto para firmar")
                return

            algorithm = self.sign_algorithm_var.get()
            signature = self.signature_manager.sign_data(data, algorithm)

            self.sign_result.delete("1.0", tk.END)
            self.sign_result.insert(tk.END, signature)
            self.status_var.set("Datos firmados exitosamente")
        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar: {str(e)}")

    def verify_signature_func(self):
        try:
            data = self.verify_text.get("1.0", tk.END).strip()
            signature = self.verify_signature.get("1.0", tk.END).strip()

            if not data or not signature:
                messagebox.showwarning("Advertencia", "Ingrese texto y firma para verificar")
                return

            is_valid, algorithm = self.signature_manager.verify_signature(data, signature)

            self.verify_result.delete("1.0", tk.END)
            if is_valid:
                self.verify_result.insert(tk.END, f"✅ FIRMA VÁLIDA\n\n")
                self.verify_result.insert(tk.END, f"Algoritmo: {algorithm}\n")
                self.verify_result.insert(tk.END, "El documento no ha sido modificado.")
                self.verify_result.tag_configure("green", foreground="green")
                self.verify_result.tag_add("green", "1.0", "1.end")
            else:
                self.verify_result.insert(tk.END, "❌ FIRMA INVÁLIDA\n\n")
                self.verify_result.insert(tk.END, "La firma no es válida o el documento ha sido modificado.")
                self.verify_result.tag_configure("red", foreground="red")
                self.verify_result.tag_add("red", "1.0", "1.end")

            self.status_var.set("Verificación completada")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar: {str(e)}")

    def generate_keys(self):
        try:
            self.signature_manager.generate_keys()
            self.key_status.configure(text="Estado: Claves generadas ✓", foreground='green')
            self.status_var.set("Par de claves RSA generado exitosamente")
            messagebox.showinfo("Éxito", "Par de claves RSA generado exitosamente")
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar claves: {str(e)}")

    def save_keys(self):
        try:
            # Guardar clave privada
            private_path = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem")],
                title="Guardar Clave Privada"
            )
            if private_path:
                self.signature_manager.save_private_key(private_path)

            # Guardar clave pública
            public_path = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem")],
                title="Guardar Clave Pública"
            )
            if public_path:
                self.signature_manager.save_public_key(public_path)

            if private_path or public_path:
                messagebox.showinfo("Éxito", "Claves guardadas exitosamente")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar claves: {str(e)}")

    def load_keys(self):
        try:
            filepath = filedialog.askopenfilename(
                filetypes=[("PEM files", "*.pem")],
                title="Cargar Clave Privada"
            )
            if filepath:
                self.signature_manager.load_private_key(filepath)
                self.key_status.configure(text="Estado: Claves cargadas ✓", foreground='green')
                self.status_var.set("Claves cargadas exitosamente")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar claves: {str(e)}")

    def save_signature(self):
        signature = self.sign_result.get("1.0", tk.END).strip()
        if not signature:
            messagebox.showwarning("Advertencia", "No hay firma para guardar")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".sig",
            filetypes=[("Signature files", "*.sig")]
        )
        if filepath:
            with open(filepath, 'w') as f:
                f.write(signature)
            messagebox.showinfo("Éxito", "Firma guardada exitosamente")

    def load_signature(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("Signature files", "*.sig")]
        )
        if filepath:
            with open(filepath, 'r') as f:
                signature = f.read()
            self.verify_signature.delete("1.0", tk.END)
            self.verify_signature.insert(tk.END, signature)

    def copy_to_clipboard(self, text):
        self.parent.clipboard_clear()
        self.parent.clipboard_append(text)
        self.status_var.set("Copiado al portapapeles")