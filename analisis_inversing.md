# Análisis de Ingeniería Inversa - MalTester 2.0

## Información General

**Programa:** MalTester2.exe  
**Tamaño:** 17,449,340 bytes (~16.6 MB)  
**Repositorio:** https://github.com/bun39/MalTester-2.0  
**Fecha de compilación estimada:** Mayo 2020 (timestamp: 1589228800)

---

## Características del Ejecutable

### Cabecera PE
| Campo | Valor |
|-------|-------|
| Tipo | PE32+ (64-bit) |
| Arquitectura | AMD64 (x86-64) |
| Machine | 0x8664 |
| Número de secciones | 10 |
| Entry Point RVA | 0x0208D0B0 |
| Image Base | 0x0000000140000000 |

### Observaciones de la Estructura PE
- Las secciones tienen valores de VirtualSize = 0, lo cual es atípico
- Las Virtual Addresses son inusuales, sugiriendo que el binario está **empaquetado/protegido**
- El Entry Point muy alto (0x0208D0B0) indica código de desempaquetado en tiempo de ejecución

---

## Protección y Ofuscación

### Nivel de Protección: ALTO

Según el README.txt del autor:
> "Note that some AV solutions may detect this program as malware due to the software protection I have used to deter reverse engineering of the code by newbies."

### Características detectadas:
1. **Empaquetado:** Estructura de secciones no estándar
2. **Ofuscación de cadenas:** La mayoría de las cadenas están codificadas/ofuscadas en el binario
3. **Sin código fuente disponible:** Solo existe el ejecutable compilado

---

## Funcionalidad del Programa (Según README)

El programa MalTester 2.0 tiene las siguientes funciones:

1. **Propósito:** Automatizar pruebas de detección de malware por soluciones AV
2. **Funcionamiento:**
   - Escanea el directorio donde se encuentra (no subdirectorios)
   - Busca archivos ejecutables (.exe)
   - Los ejecuta para probar si el antivirus los detecta
   - Registra los resultados en `MalTester2-log.txt`
3. **Requisitos:**
   - Debe ejecutarse como administrador
   - Debe estar en el mismo directorio que las muestras de malware
4. **Advertencia:** El programa ejecuta malware real para pruebas

---

## Análisis de Cadenas Visibles

### Cadenas encontradas en texto claro:
- `.imports` - Sección de tabla de importaciones
- `.boot` - Sección de recursos/boot
- `MalTest` - Parte del nombre del programa
- `This program cannot be run in DOS mode.` - Mensaje estándar DOS stub
- `Rich` - Marca de compilador Visual Studio

### Cadenas no disponibles:
La mayor parte del contenido está ofuscado/cifrado, incluyendo:
- Nombres de funciones importadas
- Cadenas de UI
- Nombres de archivos

---

## Posibilidad: Ejecutable de Python Compilado

Aunque no se encontraron cadenas claras de Python, existe la posibilidad de que sea un ejecutable compilado de Python (Py2exe, PyInstaller, etc.) ya que:
- Es una herramienta simple de línea de comandos
- El autor quería proteger el código fuente
- Los programas compilados de Python tienen estructuras PE similares

### Dependencias Externas

Basado en el análisis básico, el programa parece ser:
- **Compilado con:** Visual Studio (indicado por "Rich" marker)
- **Posible lenguaje:** C/C++ o Python compilado
- **Framework:** No se detectó .NET (BadImageFormatException al intentar cargar)

---

## Descripción Funcional del Programa

Según lo que describes y el README:

### Propósito:
Herramienta de **pruebas de seguridad en entorno aislado** para verificar la efectividad de soluciones antivirus.

### Funcionamiento detallado:
1. **Escaneo:** Detecta y cuenta todos los archivos .exe en la carpeta
2. **Ejecución secuencial:** Ejecuta cada archivo de forma ordenada
3. **Monitoreo:** Verifica si el antivirus bloquea o permite cada archivo
4. **Progreso:** Muestra archivos ejecutados vs. archivos pendientes
5. **Logging:** Registra nombre y ruta de cada archivo procesado

### Métricas que genera:
- **Total de archivos** en la carpeta
- **Archivos ejecutados**
- **Archivos pendientes** por ejecutar  
- **Porcentaje de bloqueo:** (Bloqueados / Total) × 100
- **Efectividad del antivirus:** Mide qué tan bien detecta muestras

### Uso para comparar antivirus:
Con la **misma carpeta de muestras**, se puede:
- Probar diferentes antivirus
- Comparar resultados
- Evaluar cuál detecta más amenazas
- Medir efectividad en mismo entorno

### Uso típico:
- PC aislado (sandbox)
- Analizar muestras de malware de forma segura
- Probar efectividad del antivirus
- Verificar si procesos son sospechosos/peligrosos

### Características:
- **Interfaz:** Línea de comandos (CLI)
- **Simplicidad:** Programa simple y directo
- **Requiere:** Permisos de administrador

---

1. **Sin código fuente:** Solo está disponible el ejecutable compilado
2. **Binario protegido:** El autor implementó protección anti-reversing
3. **Herramientas limitadas:** No se contó con herramientas especializadas como IDA Pro, Ghidra, o debuggers

---

## Recomendaciones para Análisis Futuro

Si deseas realizar un análisis más profundo:

1. **Desempaquetado:** Ejecutar el programa en un sandbox y dump de memoria
2. **Herramientas sugeridas:**
   - Ghidra (gratuita)
   - IDA Pro (comercial)
   - x64dbg (depurador)
   - Process Hacker (análisis de memoria)
3. **Análisis dinámico:** Ejecutar en VM y monitorear comportamiento

---

## Información del README Original

```
To run a malware test similar to The PC Security Channel's malex.py script, 
put this executable in the same directory as your malware samples, and double 
click it to run. DO NOT DOUBLE CLICK ANY MALWARE! The executable will be run, 
parse the directory (not subfolders) for executables, test them to see if 
your AV solution detects and blocks them, and log the results to 
MalTester2-log.txt in the same directory as everything else.

Make sure that this program is run as administrator, otherwise there may be bugs.

THIS PROGRAM IS DESIGNED TO EXECUTE MALWARE AND DETERMINE HOW GOOD AN 
ANTIMALWARE SOLUTION'S DETECTION IS! PLEASE DO NOT RUN THIS PROGRAM IF YOU 
DO NOT KNOW WHAT YOU ARE DOING! I TAKE NO RESPONSIBILITY FOR INFECTED MACHINES!
```

---

*Análisis realizado el 2026-03-09*
