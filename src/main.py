import tkinter as tk
from tkinter import ttk, scrolledtext

# Importar clases de pestañas
from src.gui.text_hash_tab import TextHashTab
from src.gui.file_hash_tab import FileHashTab
from src.gui.verify_tab import VerifyTab
from src.gui.benchmark_tab import BenchmarkTab
from src.gui.history_tab import HistoryTab


class HashingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aplicación de Hashing")
        self.root.geometry("850x650")
        self.root.configure(bg="#f0f2f5")

        # Configuración de estilo
        self.setup_styles()

        # Algoritmos de hash disponibles
        self.hash_algorithms = ["SHA-256", "SHA-512", "SHA-3", "MD5"]

        self.create_widgets()

    def setup_styles(self):
        """Configura los estilos de la aplicación"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f0f2f5')
        self.style.configure('TButton', font=('Segoe UI', 10), background='#4a86e8')
        self.style.configure('TLabel', font=('Segoe UI', 10), background='#f0f2f5')
        self.style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'), background='#f0f2f5')
        self.style.configure('Title.TLabel', font=('Segoe UI', 20, 'bold'), background='#f0f2f5', foreground='#4a86e8')

    def create_widgets(self):
        """Crea los widgets principales de la aplicación"""
        # Frame principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Título de la aplicación
        title_label = ttk.Label(main_frame, text="Hashing", style='Title.TLabel')
        title_label.pack(pady=(0, 20))

        # Notebook para pestañas
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Barra de estado
        self.status_var = tk.StringVar()
        self.status_var.set("Listo")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))

        # Crear pestañas
        self.setup_tabs()

        # Menú de ayuda
        self.create_menu()

    def setup_tabs(self):
        """Configura las pestañas de la aplicación"""
        # Pestaña de hashing de texto
        text_tab = ttk.Frame(self.notebook)
        self.notebook.add(text_tab, text="Hashing de Texto")
        self.text_hash_tab = TextHashTab(text_tab, self.hash_algorithms, self.status_var)

        # Pestaña de hashing de archivos
        file_tab = ttk.Frame(self.notebook)
        self.notebook.add(file_tab, text="Hashing de Archivos")
        self.file_hash_tab = FileHashTab(file_tab, self.hash_algorithms, self.status_var)

        # Pestaña de verificación
        verify_tab = ttk.Frame(self.notebook)
        self.notebook.add(verify_tab, text="Verificación")
        self.verify_tab = VerifyTab(verify_tab, self.hash_algorithms, self.status_var)

        # Pestaña de benchmark
        benchmark_tab = ttk.Frame(self.notebook)
        self.notebook.add(benchmark_tab, text="Benchmark")
        self.benchmark_tab = BenchmarkTab(benchmark_tab, self.hash_algorithms, self.status_var)

        # Pestaña de historial
        history_tab = ttk.Frame(self.notebook)
        self.notebook.add(history_tab, text="Historial")
        self.history_tab = HistoryTab(history_tab, self.hash_algorithms, self.status_var)

    def create_menu(self):
        """Crea el menú de la aplicación"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Menú Archivo
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Opcion", menu=file_menu)
        file_menu.add_command(label="Salir", command=self.root.quit)

        # Menú Ayuda
        help_menu = tk.Menu(menubar, tearoff=0)




# Punto de inicio
if __name__ == "__main__":
    root = tk.Tk()
    app = HashingApp(root)
    root.mainloop()