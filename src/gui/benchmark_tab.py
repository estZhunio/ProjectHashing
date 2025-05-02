import time
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

        # Información educativa sobre algoritmos de hash
        self.algorithm_info = {
            "SHA-256": {
                "seguridad": "Alta",
                "velocidad": "Media",
                "uso": "Blockchain, SSL/TLS, Firma Digital",
                "bits": 256,
                "familia": "SHA-2"
            },
            "SHA-512": {
                "seguridad": "Muy Alta",
                "velocidad": "Media-Baja",
                "uso": "Seguridad de archivos, Certificados",
                "bits": 512,
                "familia": "SHA-2"
            },
            "SHA-3": {
                "seguridad": "Muy Alta",
                "velocidad": "Media",
                "uso": "Aplicaciones criptográficas modernas",
                "bits": 256,
                "familia": "Keccak"
            },
            "MD5": {
                "seguridad": "Obsoleta",
                "velocidad": "Alta",
                "uso": "Checksums (NO para seguridad)",
                "bits": 128,
                "familia": "MD"
            },
            "SHA-1": {
                "seguridad": "Baja",
                "velocidad": "Alta",
                "uso": "Migrar a SHA-2 o SHA-3",
                "bits": 160,
                "familia": "SHA-1"
            },
            "bcrypt": {
                "seguridad": "Alta (Contraseñas)",
                "velocidad": "Lenta (Intencional)",
                "uso": "Almacenamiento de contraseñas",
                "bits": "Variable",
                "familia": "Password Hashing"
            },
            "Argon2": {
                "seguridad": "Muy Alta (Contraseñas)",
                "velocidad": "Configurable",
                "uso": "Contraseñas (Estándar moderno)",
                "bits": "Variable",
                "familia": "Password Hashing"
            },
            "BLAKE2": {
                "seguridad": "Alta",
                "velocidad": "Muy Alta",
                "uso": "Alternativa moderna a MD5/SHA",
                "bits": 256,
                "familia": "BLAKE"
            },
            "BLAKE3": {
                "seguridad": "Alta",
                "velocidad": "Extremadamente Alta",
                "uso": "Aplicaciones de alto rendimiento",
                "bits": 256,
                "familia": "BLAKE"
            }
        }

        self.setup_ui()

    def setup_ui(self):
        frame = ttk.Frame(self.parent, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Header con título y descripción
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(header_frame, text="Laboratorio de Rendimiento de Algoritmos Hash",
                  style='Header.TLabel', font=('Arial', 14, 'bold')).pack(anchor=tk.W)
        ttk.Label(header_frame,
                  text="Compara la velocidad y eficiencia de diferentes algoritmos de hashing",
                  font=('Arial', 10)).pack(anchor=tk.W)

        # Panel principal dividido en dos secciones
        main_panel = ttk.PanedWindow(frame, orient=tk.HORIZONTAL)
        main_panel.pack(fill=tk.BOTH, expand=True, pady=5)

        # Sección izquierda: Controles
        left_panel = ttk.Frame(main_panel)
        main_panel.add(left_panel, weight=1)

        # Opciones de benchmark
        control_frame = ttk.LabelFrame(left_panel, text="Configuración del Benchmark", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # Tipo de entrada
        self.benchmark_option = tk.StringVar(value="text")
        ttk.Label(control_frame, text="Tipo de entrada:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        radio_frame = ttk.Frame(control_frame)
        radio_frame.pack(fill=tk.X, pady=5)
        ttk.Radiobutton(radio_frame, text="Texto", variable=self.benchmark_option, value="text",
                        command=self.toggle_benchmark_input).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="Archivo", variable=self.benchmark_option, value="file",
                        command=self.toggle_benchmark_input).pack(side=tk.LEFT, padx=5)

        # Entrada para benchmark
        input_frame = ttk.LabelFrame(control_frame, text="Datos de entrada", padding=5)
        input_frame.pack(fill=tk.X, pady=5)

        # Para texto
        self.benchmark_text_frame = ttk.Frame(input_frame)
        self.benchmark_text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.benchmark_text = scrolledtext.ScrolledText(self.benchmark_text_frame, height=4, width=40, wrap=tk.WORD)
        self.benchmark_text.pack(fill=tk.BOTH, expand=True)
        self.benchmark_text.insert("1.0", "Texto de ejemplo para comparar algoritmos de hash")

        # Para archivo
        self.benchmark_file_frame = ttk.Frame(input_frame)
        self.benchmark_file_var = tk.StringVar()
        file_entry = ttk.Entry(self.benchmark_file_frame, textvariable=self.benchmark_file_var, width=30)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        browse_button = ttk.Button(self.benchmark_file_frame, text="Examinar", command=self.browse_benchmark_file)
        browse_button.pack(side=tk.RIGHT)

        # Configuración de iteraciones
        config_frame = ttk.Frame(control_frame)
        config_frame.pack(fill=tk.X, pady=5)

        ttk.Label(config_frame, text="Iteraciones:").pack(side=tk.LEFT, padx=5)
        self.iterations_var = tk.StringVar(value="5")
        self.iterations_spinbox = ttk.Spinbox(config_frame, from_=1, to=50, textvariable=self.iterations_var, width=5)
        self.iterations_spinbox.pack(side=tk.LEFT, padx=5)

        # Info sobre iteraciones
        ttk.Label(config_frame, text="(Más iteraciones = Mayor precisión)",
                  font=('Arial', 8, 'italic')).pack(side=tk.LEFT)

        # Botón de ejecutar
        run_frame = ttk.Frame(control_frame)
        run_frame.pack(fill=tk.X, pady=10)
        run_button = ttk.Button(run_frame, text="🚀 Ejecutar Benchmark",
                                command=self.run_benchmark, style='Accent.TButton')
        run_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Sección derecha: Resultados
        right_panel = ttk.Frame(main_panel)
        main_panel.add(right_panel, weight=2)

        # Notebook para resultados
        results_notebook = ttk.Notebook(right_panel)
        results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Pestaña de resultados de texto
        text_results_tab = ttk.Frame(results_notebook)
        results_notebook.add(text_results_tab, text="📊 Resultados")
        self.benchmark_result = scrolledtext.ScrolledText(text_results_tab, height=15, width=60)
        self.benchmark_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Pestaña de gráficos
        graph_tab = ttk.Frame(results_notebook)
        results_notebook.add(graph_tab, text="📈 Gráficos")
        self.graph_frame = ttk.Frame(graph_tab)
        self.graph_frame.pack(fill=tk.BOTH, expand=True)

        # Pestaña de análisis educativo
        education_tab = ttk.Frame(results_notebook)
        results_notebook.add(education_tab, text="🎓 Análisis Educativo")
        self.education_frame = ttk.Frame(education_tab)
        self.education_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Panel de información de algoritmos
        info_panel = ttk.LabelFrame(frame, text="📚 Información de Algoritmos", padding=10)
        info_panel.pack(fill=tk.X, pady=10)

        info_text = """
        💡 Tipos de Algoritmos Hash:
        • Funciones de Hash Criptográficas: SHA-256, SHA-512, SHA-3, BLAKE2/3
        • Funciones de Hash para Contraseñas: bcrypt, Argon2
        • Funciones de Hash Obsoletas: MD5, SHA-1

        ⚡ Características importantes:
        • Velocidad vs Seguridad: Las funciones más rápidas no siempre son las más seguras
        • Hash para contraseñas deben ser lentas (resistencia a ataques de fuerza bruta)
        • El tamaño del hash afecta la seguridad y el almacenamiento
        """
        info_label = ttk.Label(info_panel, text=info_text, justify=tk.LEFT)
        info_label.pack(fill=tk.X)

        # Inicialmente mostrar la opción de texto
        self.toggle_benchmark_input()

    def toggle_benchmark_input(self):
        option = self.benchmark_option.get()
        self.benchmark_text_frame.pack_forget()
        self.benchmark_file_frame.pack_forget()

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
        self.benchmark_result.insert(tk.END, "🔄 Ejecutando benchmark...\n\n")
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
                self.display_text_results(resultados, text)
                self.plot_text_results(resultados)
                self.show_educational_analysis(resultados)

            elif option == "file":
                filepath = self.benchmark_file_var.get()
                if not filepath or not os.path.isfile(filepath):
                    messagebox.showwarning("Advertencia", "Por favor seleccione un archivo válido.")
                    return

                resultados = benchmark_archivo(filepath, self.algorithms, iterations)
                self.display_file_results(resultados, filepath)
                self.plot_file_results(resultados)
                self.show_educational_analysis(resultados)

            self.status_var.set("✅ Benchmark completado")

        except Exception as e:
            messagebox.showerror("Error", f"Error durante el benchmark: {str(e)}")
            self.status_var.set("❌ Error en el benchmark")

    def display_text_results(self, resultados, text):
        self.benchmark_result.delete("1.0", tk.END)
        self.benchmark_result.insert(tk.END, "🧪 RESULTADOS DEL BENCHMARK DE TEXTO\n")
        self.benchmark_result.insert(tk.END, "=" * 50 + "\n\n")

        # Información del input
        self.benchmark_result.insert(tk.END, f"📝 Datos de entrada:\n")
        self.benchmark_result.insert(tk.END, f"   • Longitud: {len(text)} caracteres\n")
        self.benchmark_result.insert(tk.END, f"   • Tamaño: {len(text.encode('utf-8'))} bytes\n\n")

        # Mostrar resultados con emojis y formato mejorado
        for i, (algoritmo, tiempo, desviacion, hash_valor) in enumerate(resultados):
            emoji = "🥇" if i == 0 else "🥈" if i == 1 else "🥉" if i == 2 else "  "

            self.benchmark_result.insert(tk.END, f"{emoji} {i + 1}. {algoritmo}\n")
            self.benchmark_result.insert(tk.END, f"   ⏱️ Tiempo: {tiempo:.8f} segundos\n")
            self.benchmark_result.insert(tk.END, f"   📊 Desviación: ±{desviacion:.8f}\n")
            self.benchmark_result.insert(tk.END, f"   🔑 Hash: {hash_valor[:32]}...\n")
            self.benchmark_result.insert(tk.END, f"   📏 Longitud: {len(hash_valor)} caracteres\n")

            # Agregar info del algoritmo si está disponible
            if algoritmo in self.algorithm_info:
                info = self.algorithm_info[algoritmo]
                self.benchmark_result.insert(tk.END, f"   ℹ️ Seguridad: {info['seguridad']}\n")
                self.benchmark_result.insert(tk.END, f"   💻 Uso: {info['uso']}\n")

            self.benchmark_result.insert(tk.END, "\n")

        # Conclusiones
        fastest = resultados[0][0]
        slowest = resultados[-1][0]

        self.benchmark_result.insert(tk.END, "📊 ANÁLISIS DE RESULTADOS:\n")
        self.benchmark_result.insert(tk.END, "=" * 30 + "\n")
        self.benchmark_result.insert(tk.END, f"🚀 Más rápido: {fastest}\n")
        self.benchmark_result.insert(tk.END, f"🐢 Más lento: {slowest}\n")

        if fastest == "MD5":
            self.benchmark_result.insert(tk.END, "⚠️ MD5 es rápido pero NO seguro para aplicaciones criptográficas\n")
        if fastest in ["BLAKE2", "BLAKE3"]:
            self.benchmark_result.insert(tk.END, "✅ BLAKE es rápido Y seguro - excelente elección moderna\n")
        if slowest in ["bcrypt", "Argon2"]:
            self.benchmark_result.insert(tk.END, "✅ La lentitud es intencional para proteger contraseñas\n")

    def display_file_results(self, resultados, filepath):
        self.benchmark_result.delete("1.0", tk.END)
        self.benchmark_result.insert(tk.END, "📂 RESULTADOS DEL BENCHMARK DE ARCHIVO\n")
        self.benchmark_result.insert(tk.END, "=" * 50 + "\n\n")

        # Información del archivo
        file_size = os.path.getsize(filepath)
        self.benchmark_result.insert(tk.END, f"📄 Archivo: {os.path.basename(filepath)}\n")
        self.benchmark_result.insert(tk.END, f"   • Tamaño: {file_size / 1024:.2f} KB\n\n")

        for i, (algoritmo, tiempo, desviacion, velocidad, hash_valor) in enumerate(resultados):
            emoji = "🥇" if i == 0 else "🥈" if i == 1 else "🥉" if i == 2 else "  "

            self.benchmark_result.insert(tk.END, f"{emoji} {i + 1}. {algoritmo}\n")
            self.benchmark_result.insert(tk.END, f"   ⏱️ Tiempo: {tiempo:.8f} segundos\n")
            self.benchmark_result.insert(tk.END, f"   📊 Desviación: ±{desviacion:.8f}\n")
            self.benchmark_result.insert(tk.END, f"   ⚡ Velocidad: {velocidad:.2f} MB/s\n")
            self.benchmark_result.insert(tk.END, f"   🔑 Hash: {hash_valor[:32]}...\n")

            if algoritmo in self.algorithm_info:
                info = self.algorithm_info[algoritmo]
                self.benchmark_result.insert(tk.END, f"   ℹ️ Seguridad: {info['seguridad']}\n")

            self.benchmark_result.insert(tk.END, "\n")

    def plot_text_results(self, resultados):
        for widget in self.graph_frame.winfo_children():
            widget.destroy()

        plt.style.use('seaborn-v0_8-darkgrid')
        fig, ax = plt.subplots(figsize=(10, 6), dpi=100)

        # Preparar datos
        algoritmos = [r[0] for r in resultados]
        tiempos = [r[1] for r in resultados]
        desviaciones = [r[2] for r in resultados]

        # Colores basados en seguridad
        colores = []
        for alg in algoritmos:
            if alg in self.algorithm_info:
                seg = self.algorithm_info[alg]['seguridad']
                if 'Alta' in seg:
                    colores.append('#2ecc71')  # Verde
                elif 'Media' in seg:
                    colores.append('#f39c12')  # Naranja
                else:
                    colores.append('#e74c3c')  # Rojo
            else:
                colores.append('#3498db')  # Azul por defecto

        # Crear gráfico de barras
        bars = ax.bar(algoritmos, tiempos, yerr=desviaciones, capsize=5,
                      color=colores, edgecolor='black', linewidth=1, alpha=0.8)

        # Personalizar gráfico
        ax.set_title('Comparación de Rendimiento de Algoritmos Hash', fontsize=16, fontweight='bold', pad=20)
        ax.set_xlabel('Algoritmo', fontsize=12)
        ax.set_ylabel('Tiempo (segundos)', fontsize=12)
        ax.grid(True, linestyle='--', alpha=0.7)

        # Rotar etiquetas del eje X
        plt.xticks(rotation=45, ha='right')

        # Añadir valores sobre las barras
        for bar, tiempo in zip(bars, tiempos):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height,
                    f'{tiempo:.8f}',
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

        # Añadir leyenda de colores
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#2ecc71', label='Alta Seguridad'),
            Patch(facecolor='#f39c12', label='Media Seguridad'),
            Patch(facecolor='#e74c3c', label='Baja/Obsoleta')
        ]
        ax.legend(handles=legend_elements, loc='upper right')

        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        canvas.draw()

    def plot_file_results(self, resultados):
        for widget in self.graph_frame.winfo_children():
            widget.destroy()

        plt.style.use('seaborn-v0_8-darkgrid')
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 10), dpi=100)
        fig.subplots_adjust(hspace=0.4)

        # Preparar datos
        algoritmos = [r[0] for r in resultados]
        tiempos = [r[1] for r in resultados]
        velocidades = [r[3] for r in resultados]

        # Colores basados en seguridad
        colores = []
        for alg in algoritmos:
            if alg in self.algorithm_info:
                seg = self.algorithm_info[alg]['seguridad']
                if 'Alta' in seg:
                    colores.append('#2ecc71')
                elif 'Media' in seg:
                    colores.append('#f39c12')
                else:
                    colores.append('#e74c3c')
            else:
                colores.append('#3498db')

        # Gráfico 1: Tiempos
        ax1.set_title('Tiempo de Procesamiento por Algoritmo', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Tiempo (segundos)', fontsize=12)
        bars1 = ax1.bar(algoritmos, tiempos, color=colores, edgecolor='black', linewidth=1, alpha=0.8)

        for bar, tiempo in zip(bars1, tiempos):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2., height,
                     f'{tiempo:.6f}',
                     ha='center', va='bottom', fontsize=9)

        ax1.tick_params(axis='x', rotation=45)

        # Gráfico 2: Velocidades
        ax2.set_title('Velocidad de Procesamiento (MB/s)', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Velocidad (MB/s)', fontsize=12)
        bars2 = ax2.bar(algoritmos, velocidades, color=colores, edgecolor='black', linewidth=1, alpha=0.8)

        for bar, velocidad in zip(bars2, velocidades):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width() / 2., height,
                     f'{velocidad:.2f}',
                     ha='center', va='bottom', fontsize=9)

        ax2.tick_params(axis='x', rotation=45)

        # Título principal
        fig.suptitle('Análisis de Rendimiento en Archivos', fontsize=16, fontweight='bold')

        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        canvas.draw()

    def show_educational_analysis(self, resultados):
        # Limpiar frame educativo
        for widget in self.education_frame.winfo_children():
            widget.destroy()

        # Crear notebook para análisis educativo
        edu_notebook = ttk.Notebook(self.education_frame)
        edu_notebook.pack(fill=tk.BOTH, expand=True)

        # Pestaña de Comparación de Algoritmos
        comparison_tab = ttk.Frame(edu_notebook)
        edu_notebook.add(comparison_tab, text="Comparación")

        comparison_text = scrolledtext.ScrolledText(comparison_tab, height=20, width=80, wrap=tk.WORD)
        comparison_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        comparison_text.insert(tk.END, "🔬 ANÁLISIS COMPARATIVO DE ALGORITMOS HASH\n")
        comparison_text.insert(tk.END, "=" * 50 + "\n\n")

        # Ordenar por velocidad
        sorted_by_speed = sorted(resultados, key=lambda x: x[1])

        comparison_text.insert(tk.END, "📊 RANKING POR VELOCIDAD:\n")
        comparison_text.insert(tk.END, "-" * 30 + "\n")
        for i, (alg, tiempo, _, *_) in enumerate(sorted_by_speed):
            emoji = "🥇" if i == 0 else "🥈" if i == 1 else "🥉" if i == 2 else f"{i + 1}."
            comparison_text.insert(tk.END, f"{emoji} {alg}: {tiempo:.8f} segundos\n")

            if alg in self.algorithm_info:
                info = self.algorithm_info[alg]
                comparison_text.insert(tk.END, f"   • Familia: {info['familia']}\n")
                comparison_text.insert(tk.END, f"   • Bits de salida: {info['bits']}\n")
                comparison_text.insert(tk.END, f"   • Seguridad: {info['seguridad']}\n")
                comparison_text.insert(tk.END, f"   • Uso recomendado: {info['uso']}\n\n")

        # Pestaña de Recomendaciones
        recommendations_tab = ttk.Frame(edu_notebook)
        edu_notebook.add(recommendations_tab, text="Recomendaciones")

        rec_text = scrolledtext.ScrolledText(recommendations_tab, height=20, width=80, wrap=tk.WORD)
        rec_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        rec_text.insert(tk.END, "💡 RECOMENDACIONES DE USO\n")
        rec_text.insert(tk.END, "=" * 50 + "\n\n")

        rec_text.insert(tk.END, "🔒 PARA APLICACIONES DE SEGURIDAD:\n")
        rec_text.insert(tk.END, "• SHA-256/SHA-512: Estándar industrial para seguridad general\n")
        rec_text.insert(tk.END, "• SHA-3: Máxima seguridad, resistente a ataques cuánticos\n")
        rec_text.insert(tk.END, "• BLAKE2/BLAKE3: Alternativas modernas, rápidas y seguras\n\n")

        rec_text.insert(tk.END, "🔑 PARA ALMACENAMIENTO DE CONTRASEÑAS:\n")
        rec_text.insert(tk.END, "• Argon2: Ganador de la competición de hashing de contraseñas\n")
        rec_text.insert(tk.END, "• bcrypt: Probado en el tiempo, ampliamente soportado\n")
        rec_text.insert(tk.END, "• NUNCA usar: MD5, SHA-1, o algoritmos rápidos\n\n")

        rec_text.insert(tk.END, "⚡ PARA VERIFICACIÓN DE INTEGRIDAD RÁPIDA:\n")
        rec_text.insert(tk.END, "• BLAKE3: Extremadamente rápido, seguro\n")
        rec_text.insert(tk.END, "• MD5: Solo para aplicaciones no críticas (checksums simples)\n\n")

        rec_text.insert(tk.END, "⚠️ ALGORITMOS A EVITAR:\n")
        rec_text.insert(tk.END, "• MD5: Vulnerable a colisiones, obsoleto para seguridad\n")
        rec_text.insert(tk.END, "• SHA-1: Comprometido, migrar a SHA-2 o superior\n")

        # Pestaña de Conceptos
        concepts_tab = ttk.Frame(edu_notebook)
        edu_notebook.add(concepts_tab, text="Conceptos Clave")

        concepts_text = scrolledtext.ScrolledText(concepts_tab, height=20, width=80, wrap=tk.WORD)
        concepts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        concepts_text.insert(tk.END, "📚 CONCEPTOS CLAVE DE HASHING\n")
        concepts_text.insert(tk.END, "=" * 50 + "\n\n")

        concepts_text.insert(tk.END, "🎯 PROPIEDADES DE UN BUEN HASH:\n")
        concepts_text.insert(tk.END, "1. Determinista: Mismo input = mismo output\n")
        concepts_text.insert(tk.END, "2. Efecto avalancha: Pequeño cambio = gran diferencia\n")
        concepts_text.insert(tk.END, "3. Unidireccional: Imposible revertir\n")
        concepts_text.insert(tk.END, "4. Resistente a colisiones: Difícil encontrar duplicados\n\n")

        concepts_text.insert(tk.END, "🔐 TIPOS DE ATAQUES:\n")
        concepts_text.insert(tk.END, "• Ataque de fuerza bruta: Probar todas las combinaciones\n")
        concepts_text.insert(tk.END, "• Ataque de diccionario: Usar palabras comunes\n")
        concepts_text.insert(tk.END, "• Ataque por colisión: Encontrar dos inputs con mismo hash\n")
        concepts_text.insert(tk.END, "• Ataque de preimagen: Encontrar input para un hash dado\n")
        concepts_text.insert(tk.END, "• Rainbow tables: Tablas precalculadas de hashes\n\n")

        concepts_text.insert(tk.END, "📏 TAMAÑO DEL HASH:\n")
        concepts_text.insert(tk.END, "• MD5: 128 bits (32 caracteres hex)\n")
        concepts_text.insert(tk.END, "• SHA-1: 160 bits (40 caracteres hex)\n")
        concepts_text.insert(tk.END, "• SHA-256: 256 bits (64 caracteres hex)\n")
        concepts_text.insert(tk.END, "• SHA-512: 512 bits (128 caracteres hex)\n\n")

        concepts_text.insert(tk.END, "⚖️ VELOCIDAD VS SEGURIDAD:\n")
        concepts_text.insert(tk.END, "• Hash rápido: Bueno para integridad de archivos\n")
        concepts_text.insert(tk.END, "• Hash lento: Necesario para contraseñas\n")
        concepts_text.insert(tk.END, "• La lentitud protege contra ataques masivos\n")

        # Deshabilitar edición en todos los campos de texto
        comparison_text.config(state=tk.DISABLED)
        rec_text.config(state=tk.DISABLED)
        concepts_text.config(state=tk.DISABLED)

    def export_results(self, resultados):
        """Exporta los resultados a un archivo HTML"""
        try:
            filepath = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
                title="Guardar informe de benchmark"
            )

            if filepath:
                html_content = self.generate_html_report(resultados)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                messagebox.showinfo("Éxito", "Informe exportado correctamente")

        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar: {str(e)}")

    def generate_html_report(self, resultados):
        """Genera un informe HTML con los resultados"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Informe de Benchmark de Algoritmos Hash</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1, h2 { color: #333; }
                table { border-collapse: collapse; width: 100%; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .fast { color: green; }
                .slow { color: red; }
                .secure { color: blue; }
                .chart { margin: 20px 0; }
            </style>
        </head>
        <body>
            <h1>Informe de Benchmark de Algoritmos Hash</h1>
            <p>Fecha: {}</p>

            <h2>Resultados del Benchmark</h2>
            <table>
                <tr>
                    <th>Algoritmo</th>
                    <th>Tiempo (segundos)</th>
                    <th>Velocidad</th>
                    <th>Seguridad</th>
                    <th>Uso Recomendado</th>
                </tr>
        """.format(time.strftime("%Y-%m-%d %H:%M:%S"))

        for i, (alg, tiempo, *rest) in enumerate(resultados):
            info = self.algorithm_info.get(alg, {})
            speed_class = "fast" if i == 0 else "slow" if i == len(resultados) - 1 else ""
            security_class = "secure" if "Alta" in info.get('seguridad', '') else ""

            html += f"""
                <tr>
                    <td>{alg}</td>
                    <td class="{speed_class}">{tiempo:.8f}</td>
                    <td>{info.get('velocidad', 'N/A')}</td>
                    <td class="{security_class}">{info.get('seguridad', 'N/A')}</td>
                    <td>{info.get('uso', 'N/A')}</td>
                </tr>
            """

        html += """
            </table>

            <h2>Recomendaciones</h2>
            <ul>
                <li><strong>Para seguridad general:</strong> SHA-256, SHA-512, BLAKE2</li>
                <li><strong>Para contraseñas:</strong> Argon2, bcrypt</li>
                <li><strong>Para rendimiento:</strong> BLAKE3, SHA-256</li>
                <li><strong>Evitar para seguridad:</strong> MD5, SHA-1</li>
            </ul>

            <h2>Conclusiones</h2>
            <p>Este benchmark muestra claramente la relación entre velocidad y seguridad en los algoritmos de hash.
            Los algoritmos más antiguos como MD5 son rápidos pero inseguros, mientras que los algoritmos modernos
            ofrecen un mejor balance entre rendimiento y seguridad.</p>

            <footer>
                <p>Generado por la Aplicación de Hashing - Proyecto Educativo</p>
            </footer>
        </body>
        </html>
        """

        return html