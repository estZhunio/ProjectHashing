# HashMaster - Aplicación de Hashing con Interfaz Gráfica

## Descripción
HashMaster es una aplicación de escritorio completa para el cálculo, análisis y comparación de algoritmos de hash criptográficos. Desarrollada en Python con interfaz gráfica Tkinter, esta aplicación permite comprender el funcionamiento, eficiencia y seguridad de diferentes algoritmos de hash.

## Características Principales

### 1. Hashing de Texto y Archivos
- Cálculo de hash para texto ingresado por el usuario
- Cálculo de hash para archivos locales
- Soporte para algoritmos SHA-256, SHA-512, SHA-3 y MD5
- Visualización clara de resultados y opción de copiar al portapapeles

### 2. Verificación de Integridad
- Verificación de integridad para texto y archivos
- Comprobación visual de coincidencia de hashes
- Generación automática de informes de verificación

### 3. Análisis de Rendimiento
- Benchmark de los algoritmos en tiempo real
- Análisis comparativo con gráficos
- Estudio de velocidad, seguridad y distribución de bits
- Exportación de informes detallados

### 4. Base de Datos y Historial
- Almacenamiento de operaciones realizadas
- Recuperación de hashes calculados previamente
- Gestión de historial de verificaciones

## Tecnologías Utilizadas
- **Python 3**: Lenguaje de programación principal
- **Tkinter**: Biblioteca para la interfaz gráfica
- **SQLite**: Base de datos ligera para almacenamiento
- **Matplotlib**: Generación de gráficos y visualizaciones
- **Hashlib**: Biblioteca estándar de Python para funciones hash

## Algoritmos Implementados

### SHA-256
- Parte de la familia SHA-2 (Secure Hash Algorithm 2)
- 256 bits de longitud (64 caracteres hexadecimales)
- Alta seguridad con buen rendimiento general

### SHA-512
- Versión de 512 bits de la familia SHA-2
- 128 caracteres hexadecimales
- Mayor seguridad y buen rendimiento en sistemas de 64 bits

### SHA-3 (Keccak)
- Familia más reciente de algoritmos SHA
- Estructura interna diferente a SHA-2
- Alta resistencia a tipos de ataques teóricos contra SHA-2

### MD5 (con fines comparativos)
- Algoritmo histórico de 128 bits (32 caracteres hexadecimales)
- Rápido pero vulnerable a colisiones
- Incluido solo con propósitos educativos y comparativos

## Instalación y Requisitos

### Requisitos Previos
- Python 3.6 o superior
- Bibliotecas: tkinter, matplotlib, sqlite3 (incluidas en la mayoría de instalaciones)
- Pillow (para elementos gráficos): `pip install pillow`
- Matplotlib: `pip install matplotlib`

### Instrucciones de Instalación
1. Clonar o descargar este repositorio
2. Instalar dependencias: `pip install -r requirements.txt`
3. Ejecutar la aplicación: `python -m src.main`

## Estructura del Proyecto