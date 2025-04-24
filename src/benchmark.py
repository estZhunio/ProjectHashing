import time
import os
import statistics
from src.hash_utils import calculate_hash_string, calculate_hash_file


def benchmark_texto(texto, algoritmos=None, iteraciones=5):
    """
    Realiza un benchmark de tiempo para diferentes algoritmos de hash sobre un texto.

    Args:
        texto (str): El texto para realizar el benchmark
        algoritmos (list, optional): Lista de algoritmos a probar. Por defecto ["SHA-256", "SHA-512", "SHA-3", "MD5"]
        iteraciones (int, optional): Número de iteraciones para mayor precisión

    Returns:
        list: Lista de tuplas (algoritmo, tiempo_promedio, desviacion_estandar, hash) ordenada por tiempo
    """
    if algoritmos is None:
        algoritmos = ["SHA-256", "SHA-512", "SHA-3", "MD5"]

    resultados = []

    for algoritmo in algoritmos:
        tiempos = []

        # Realizar múltiples iteraciones para obtener un promedio más preciso
        for _ in range(iteraciones):
            inicio = time.time()
            hash_valor = calculate_hash_string(texto, algoritmo)
            fin = time.time()

            tiempos.append(fin - inicio)

        # Calcular estadísticas
        tiempo_promedio = statistics.mean(tiempos)
        desviacion = statistics.stdev(tiempos) if len(tiempos) > 1 else 0

        resultados.append((algoritmo, tiempo_promedio, desviacion, hash_valor))

    # Ordenar por tiempo (más rápido primero)
    resultados.sort(key=lambda x: x[1])

    return resultados


def benchmark_archivo(ruta_archivo, algoritmos=None, iteraciones=3):
    """
    Realiza un benchmark de tiempo para diferentes algoritmos de hash sobre un archivo.

    Args:
        ruta_archivo (str): Ruta al archivo para realizar el benchmark
        algoritmos (list, optional): Lista de algoritmos a probar. Por defecto ["SHA-256", "SHA-512", "SHA-3", "MD5"]
        iteraciones (int, optional): Número de iteraciones para mayor precisión

    Returns:
        list: Lista de tuplas (algoritmo, tiempo_promedio, desviacion_estandar, velocidad_mbps, hash) ordenada por tiempo
    """
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(f"El archivo '{ruta_archivo}' no existe")

    if algoritmos is None:
        algoritmos = ["SHA-256", "SHA-512", "SHA-3", "MD5"]

    resultados = []
    tamano_archivo = os.path.getsize(ruta_archivo)
    tamano_mb = tamano_archivo / (1024 * 1024)  # Tamaño en MB

    for algoritmo in algoritmos:
        tiempos = []

        # Realizar múltiples iteraciones para obtener un promedio más preciso
        for _ in range(iteraciones):
            inicio = time.time()
            hash_valor = calculate_hash_file(ruta_archivo, algoritmo)
            fin = time.time()

            tiempos.append(fin - inicio)

        # Calcular estadísticas
        tiempo_promedio = statistics.mean(tiempos)
        desviacion = statistics.stdev(tiempos) if len(tiempos) > 1 else 0

        # Calcular velocidad en MB/s
        velocidad = tamano_mb / tiempo_promedio if tiempo_promedio > 0 else float('inf')

        resultados.append((algoritmo, tiempo_promedio, desviacion, velocidad, hash_valor))

    # Ordenar por tiempo (más rápido primero)
    resultados.sort(key=lambda x: x[1])

    return resultados


def analizar_colisiones(algoritmo, num_pruebas=100):
    """
    Realiza un análisis básico de resistencia a colisiones generando hashes aleatorios.

    Args:
        algoritmo (str): Algoritmo a probar
        num_pruebas (int): Número de hashes aleatorios a generar

    Returns:
        dict: Resultados del análisis
    """
    import random
    import string

    hashes_generados = set()
    colisiones = 0

    # Generar textos aleatorios y calcular sus hashes
    for _ in range(num_pruebas):
        # Generar una cadena aleatoria de longitud entre 5 y 50 caracteres
        longitud = random.randint(5, 50)
        texto = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(longitud))

        # Calcular el hash
        hash_valor = calculate_hash_string(texto, algoritmo)

        # Comprobar si este hash ya se ha generado (colisión)
        if hash_valor in hashes_generados:
            colisiones += 1
        else:
            hashes_generados.add(hash_valor)

        # Calcular la distribución de bits
        # (para un análisis básico de la distribución de valores)
    bits_unos = 0
    bits_ceros = 0
    total_bits = 0

    for hash_valor in hashes_generados:
        for caracter in hash_valor:
            # Convertir caracteres hexadecimales a binario
            if caracter in '0123456789abcdef':
                valor_binario = bin(int(caracter, 16))[2:].zfill(4)
                bits_unos += valor_binario.count('1')
                bits_ceros += valor_binario.count('0')
                total_bits += 4

    # Resultados
    distribucion_unos = bits_unos / total_bits if total_bits > 0 else 0

    return {
        'algoritmo': algoritmo,
        'num_pruebas': num_pruebas,
        'colisiones': colisiones,
        'distribucion_unos': distribucion_unos,
        'distribucion_ceros': 1 - distribucion_unos
    }


def comparar_algoritmos_exhaustivo(texto, archivos_prueba=None):
    """
    Realiza una comparación exhaustiva de todos los algoritmos.

    Args:
        texto (str): Texto para probar algoritmos de hash
        archivos_prueba (list, optional): Lista de rutas a archivos para probar

    Returns:
        dict: Resultados completos del análisis
    """
    algoritmos = ["SHA-256", "SHA-512", "SHA-3", "MD5"]

    resultados = {
        'texto': {},
        'archivos': {},
        'colisiones': {},
        'bits': {}
    }

    # Benchmark de texto
    benchmark_texto_resultados = benchmark_texto(texto, algoritmos, iteraciones=10)
    for algoritmo, tiempo, desviacion, hash_valor in benchmark_texto_resultados:
        resultados['texto'][algoritmo] = {
            'tiempo': tiempo,
            'desviacion': desviacion,
            'hash': hash_valor
        }

    # Benchmark de archivos
    if archivos_prueba:
        for archivo in archivos_prueba:
            if os.path.exists(archivo):
                try:
                    nombre_archivo = os.path.basename(archivo)
                    resultados['archivos'][nombre_archivo] = {}

                    benchmark_archivo_resultados = benchmark_archivo(archivo, algoritmos, iteraciones=3)
                    for algoritmo, tiempo, desviacion, velocidad, hash_valor in benchmark_archivo_resultados:
                        resultados['archivos'][nombre_archivo][algoritmo] = {
                            'tiempo': tiempo,
                            'desviacion': desviacion,
                            'velocidad': velocidad,
                            'hash': hash_valor
                        }
                except Exception as e:
                    resultados['archivos'][nombre_archivo] = {
                        'error': str(e)
                    }

    # Análisis de colisiones y distribución de bits
    for algoritmo in algoritmos:
        resultados['colisiones'][algoritmo] = analizar_colisiones(algoritmo, num_pruebas=200)

    # Calcular el más rápido y más lento
    algoritmo_mas_rapido = min(resultados['texto'].items(), key=lambda x: x[1]['tiempo'])[0]
    algoritmo_mas_lento = max(resultados['texto'].items(), key=lambda x: x[1]['tiempo'])[0]

    # Resumen
    resultados['resumen'] = {
        'algoritmo_mas_rapido': algoritmo_mas_rapido,
        'algoritmo_mas_lento': algoritmo_mas_lento,
        'mejores_caracteristicas': {
            'velocidad': algoritmo_mas_rapido,
            'seguridad': 'SHA-512' if 'SHA-512' in algoritmos else 'SHA-3'
        }
    }

    return resultados