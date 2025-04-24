import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from src.benchmark import benchmark_texto, benchmark_archivo
from src.db_utils import HashDatabase


class BenchmarkTab:
    def __init__(self, parent, algorithms, status_var):
        self.parent = parent
        self.algorithms = algorithms
        self.status_var = status_var
        self.db = HashDatabase()

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Comparación de Rendimiento", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))

        # Opciones de benchmark (Texto o Archivo)
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill=tk.X, pady=5)

        self.benchmark_option = tk.StringVar(value="text")
        ttk.Radiobutton(options_frame, text="Benchmark con Texto", variable=self.benchmark_option, value="text",
                        command=self.toggle_benchmark_input).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(options_frame, text="Benchmark con Archivo", variable=self.benchmark_option, value="file",
                        command=self.toggle_benchmark_input).pack(side=tk.LEFT, padx=(0, 10))

        # Entrada para benchmark
        input_frame = ttk.LabelFrame(frame, text="Entrada para Benchmark")
        input_frame.pack(fill=tk.X, expand=False, pady=10)

        # Para texto
        self.benchmark_text_frame = ttk.Frame(input_frame)
        self.benchmark_text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.benchmark_text = scrolledtext.ScrolledText(self.benchmark_text_frame, height=5, width=50, wrap=tk.WORD)
        self.benchmark_text.pack(fill=tk.BOTH, expand=True)

        # Para archivo
        self.benchmark_file_frame = ttk.Frame(input_frame)

        self.benchmark_file_var = tk.StringVar()
        file_entry = ttk.Entry(self.benchmark_file_frame, textvariable=self.benchmark_file_var, width=50)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        browse_button = ttk.Button(self.benchmark_file_frame, text="Examinar",
                                   command=self.browse_benchmark_file)
        browse_button.pack(side=tk.RIGHT)

        # Opciones de benchmark
        options_benchmark_frame = ttk.Frame(frame)
        options_benchmark_frame.pack(fill=tk.X, pady=5)

        ttk.Label(options_benchmark_frame, text="Iteraciones:").pack(side=tk.LEFT, padx=(0, 5))
        self.iterations_var = tk.StringVar(value="5")
        self.iterations_spinbox = ttk.Spinbox(options_benchmark_frame, from_=1, to=20,
                                              textvariable=self.iterations_var, width=5)
        self.iterations_spinbox.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(options_benchmark_frame, text="(Más iteraciones").pack(side=tk.LEFT)

        # Botón de ejecutar benchmark
        run_frame = ttk.Frame(frame)
        run_frame.pack(fill=tk.X, pady=5)

        run_button = ttk.Button(run_frame, text="Ejecutar Benchmark", command=self.run_benchmark)
        run_button.pack(side=tk.LEFT, padx=5)

        # Notebook para resultados (tabs para texto y gráficos)
        results_notebook = ttk.Notebook(frame)
        results_notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        # Pestaña de resultados de texto
        text_results_tab = ttk.Frame(results_notebook)
        results_notebook.add(text_results_tab, text="Resultados")

        self.benchmark_result = scrolledtext.ScrolledText(text_results_tab, height=10, width=50)
        self.benchmark_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Pestaña de gráficos
        graph_tab = ttk.Frame(results_notebook)
        results_notebook.add(graph_tab, text="Gráficos")

        self.graph_frame = ttk.Frame(graph_tab)
        self.graph_frame.pack(fill=tk.BOTH, expand=True)

        # Inicialmente mostrar la opción de texto
        self.toggle_benchmark_input()

    def toggle_benchmark_input(self):
        option = self.benchmark_option.get()

        # Ocultar todos los frames
        self.benchmark_text_frame.pack_forget()
        self.benchmark_file_frame.pack_forget()

        # Mostrar el frame correspondiente
        if option == "text":
            self.benchmark_text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        elif option == "file":
            self.benchmark_file_frame.pack(fill=tk.X, padx=5, pady=5)

    def browse_benchmark_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.benchmark_file_var.set(filepath)

    def run_benchmark(self):
        self.benchmark_result.delete("1.0", tk.END)
        self.benchmark_result.insert(tk.END, "Ejecutando benchmark...\n\n")
        self.parent.update_idletasks()

        try:
            iterations = int(self.iterations_var.get())
            if iterations < 1:
                iterations = 1

            option = self.benchmark_option.get()

            if option == "text":
                text = self.benchmark_text.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showwarning("Advertencia", "Por favor ingrese texto para el benchmark.")
                    return

                resultados = benchmark_texto(text, self.algorithms, iterations)
                self.display_text_results(resultados)
                self.plot_text_results(resultados)

            elif option == "file":
                filepath = self.benchmark_file_var.get()
                if not filepath or not os.path.isfile(filepath):
                    messagebox.showwarning("Advertencia", "Por favor seleccione un archivo válido.")
                    return

                resultados = benchmark_archivo(filepath, self.algorithms, iterations)
                self.display_file_results(resultados)
                self.plot_file_results(resultados)

            self.status_var.set("Benchmark completado")

        except Exception as e:
            messagebox.showerror("Error", f"Error durante el benchmark: {str(e)}")
            self.status_var.set("Error en el benchmark")

    def display_text_results(self, resultados):
        self.benchmark_result.delete("1.0", tk.END)
        self.benchmark_result.insert(tk.END, "Resultados del Benchmark de Texto:\n\n")

        for i, (algoritmo, tiempo, desviacion, hash_valor) in enumerate(resultados):
            self.benchmark_result.insert(tk.END, f"{i + 1}. {algoritmo}\n")
            self.benchmark_result.insert(tk.END, f"   Tiempo: {tiempo:.6f} segundos (±{desviacion:.6f})\n")
            self.benchmark_result.insert(tk.END, f"   Hash: {hash_valor}\n\n")

        # Añadir conclusión
        fastest = resultados[0][0]
        slowest = resultados[-1][0]


    def display_file_results(self, resultados):
        self.benchmark_result.delete("1.0", tk.END)
        self.benchmark_result.insert(tk.END, "Resultados del Benchmark de Archivo:\n\n")

        for i, (algoritmo, tiempo, desviacion, velocidad, hash_valor) in enumerate(resultados):
            self.benchmark_result.insert(tk.END, f"{i + 1}. {algoritmo}\n")
            self.benchmark_result.insert(tk.END, f"   Tiempo: {tiempo:.6f} segundos (±{desviacion:.6f})\n")
            self.benchmark_result.insert(tk.END, f"   Velocidad: {velocidad:.2f} MB/s\n")
            self.benchmark_result.insert(tk.END, f"   Hash: {hash_valor}\n\n")

        # Añadir conclusión
        fastest = resultados[0][0]
        slowest = resultados[-1][0]



    def plot_text_results(self, resultados):
        # Limpiar frame de gráficos
        for widget in self.graph_frame.winfo_children():
            widget.destroy()

        # Estilo visual
        plt.style.use('seaborn-v0_8-darkgrid')

        # Crear figura con un solo eje
        fig, ax1 = plt.subplots(figsize=(8, 5), dpi=100)
        fig.subplots_adjust(hspace=0.4)

        # Datos
        algoritmos = [r[0] for r in resultados]
        tiempos = [r[1] for r in resultados]
        desviaciones = [r[2] for r in resultados]
        colores = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12']

        # Gráfico de tiempos
        ax1.set_title('Análisis de Algoritmos de Hash', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Tiempo (segundos)', fontsize=12)
        ax1.grid(True, linestyle='--', alpha=0.7)

        bars = ax1.bar(algoritmos, tiempos, yerr=desviaciones, capsize=5,
                       color=colores, edgecolor='black', linewidth=1)

        for bar, tiempo in zip(bars, tiempos):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2., height + 0.000001,
                     f'{tiempo:.8f}',
                     ha='center', va='bottom', rotation=0, fontsize=9,
                     fontweight='bold')

        # Mostrar en frame
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        canvas.draw()


    def plot_file_results(self, resultados):
        # Configuración similar a plot_text_results pero para archivos
        # Limpiar frame de gráficos
        for widget in self.graph_frame.winfo_children():
            widget.destroy()

        # Configurar estilo más atractivo
        plt.style.use('seaborn-v0_8-darkgrid')

        # Crear figura con mejor relación de aspecto
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 8), dpi=100)
        fig.subplots_adjust(hspace=0.4)  # Más espacio entre gráficos

        # Datos
        algoritmos = [r[0] for r in resultados]
        tiempos = [r[1] for r in resultados]
        velocidades = [r[3] for r in resultados]

        # Colores más vivos y atractivos
        colores = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12']

        # Gráfico 1: Tiempos
        ax1.set_title('Tiempo de Procesamiento por Algoritmo', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Tiempo (segundos)', fontsize=12)
        ax1.grid(True, linestyle='--', alpha=0.7)

        # Barras con mejor estilo
        bars = ax1.bar(algoritmos, tiempos, color=colores, edgecolor='black', linewidth=1)

        # Añadir etiquetas de valor
        for bar, tiempo in zip(bars, tiempos):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2., height + 0.000001,
                     f'{tiempo:.6f}',
                     ha='center', va='bottom', rotation=0, fontsize=9,
                     fontweight='bold')

        # Gráfico 2: Velocidades
        ax2.set_title('Velocidad de Procesamiento (MB/s)', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Velocidad (MB/s)', fontsize=12)
        ax2.grid(True, linestyle='--', alpha=0.7)

        # Barras con mejor estilo
        bars2 = ax2.bar(algoritmos, velocidades, color=colores, edgecolor='black', linewidth=1)

        # Añadir etiquetas de valor
        for bar, velocidad in zip(bars2, velocidades):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width() / 2., height + velocidad * 0.03,
                     f'{velocidad:.2f}',
                     ha='center', va='bottom', rotation=0, fontsize=10,
                     fontweight='bold')

        # Título principal
        fig.suptitle('Análisis de Velocidad en Archivos', fontsize=16, fontweight='bold')

        # Mostrar en frame
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        canvas.draw()