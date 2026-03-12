#!/usr/bin/env python3
"""
MalTester Enhanced - Versión mejorada de MalTester 2.0
Características adicionales:
- Análisis de hash con VirusTotal
- Estadísticas detalladas
- Reportes en JSON y CSV
- Interfaz mejorada

Uso: python MalTesterEnhanced.py [directorio] [opciones]

Opciones:
  --api-key       API key de VirusTotal (o configurar en variable de entorno VT_API_KEY)
  --no-virustotal  Omitir análisis de VirusTotal
  --output        Archivo de salida (default: MalTesterEnhanced_log.txt)
  --json          Guardar reporte en formato JSON
  --csv           Guardar reporte en formato CSV
  --delay         Delay entre ejecuciones en segundos (default: 2)
  --timeout       Timeout para ejecución de muestras (default: 10)
"""

import os
import sys
import json
import csv
import time
import hashlib
import argparse
import subprocess
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Importación de psutil para verificación de procesos
try:
    import psutil
except ImportError:
    psutil = None
    print(f"{Colors.YELLOW}Advertencia: psutil no está instalado. La verificación de procesos será limitada.{Colors.END}")

# Configuración de VirusTotal
VT_API_URL = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"Accept": "application/json"}

class Colors:
    """Colores para terminal - desactivados para compatibilidad"""
    GREEN = ''
    RED = ''
    YELLOW = ''
    BLUE = ''
    CYAN = ''
    BOLD = ''
    END = ''
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class MalTesterEnhanced:
    """Clase principal del programa"""
    
    def __init__(self, directory: str, api_key: Optional[str] = None, 
                 use_virustotal: bool = True, delay: int = 2, 
                 timeout: int = 10):
        self.directory = Path(directory)
        self.api_key = api_key or os.environ.get('VT_API_KEY')
        self.use_virustotal = use_virustotal and bool(self.api_key)
        self.delay = delay
        self.timeout = timeout
        
        # Resultados
        self.results: List[Dict] = []
        self.stats = {
            'total': 0,
            'executed': 0,
            'blocked': 0,
            'passed': 0,
            'errors': 0,
            'vt_detections': 0
        }
        
    def calculate_hash(self, file_path: Path) -> str:
        """Calcula SHA-256 hash del archivo"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"{Colors.RED}Error calculando hash: {e}{Colors.END}")
            return ""
    
    def check_virustotal(self, file_hash: str) -> Dict:
        """Consulta hash en VirusTotal"""
        if not self.use_virustotal or not self.api_key:
            return {'available': False}
        
        url = f"{VT_API_URL}/files/{file_hash}"
        headers = {"x-apikey": self.api_key, **VT_HEADERS}
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total_engines = sum(stats.values())
                
                return {
                    'available': True,
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'undetected': stats.get('undetected', 0),
                    'total_engines': total_engines,
                    'detection_ratio': f"{malicious + suspicious}/{total_engines}",
                    'is_malicious': malicious > 0 or suspicious > 0
                }
            elif response.status_code == 404:
                return {'available': True, 'not_found': True}
        except Exception as e:
            print(f"{Colors.RED}Error consultando VirusTotal: {e}{Colors.END}")
        
        return {'available': False, 'error': str(e)}
    
    def check_process_running(self, process_name: str) -> bool:
        """Verifica si un proceso está ejecutándose (indicador de ejecución)"""
        try:
            result = subprocess.run(
                ['tasklist'], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            return process_name.lower() in result.stdout.lower()
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}Timeout verificando proceso{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.YELLOW}Error verificando proceso: {e}{Colors.END}")
            return False
    
    def analyze_file(self, file_path: Path) -> Dict:
        """Analiza un archivo individual - FOCO PRINCIPAL: Detectar si AV local bloquea"""
        result = {
            'name': file_path.name,
            'path': str(file_path.absolute()),
            'size': file_path.stat().st_size,
            'executed': False,
            'blocked': False,
            'blocked_by_av': False,  # ← Detección específica de AV
            'running_process': False,  # ← Proceso en ejecución
            'error': None,
            'vt_result': None,
            'sha256': None,
            'execution_time': 0,
            'blocked_reason': None  # Razón del bloqueo
        }
        
        # Calcular hash (para VirusTotal - complemento)
        result['sha256'] = self.calculate_hash(file_path)
        
        # Consultar VirusTotal (COMPLEMENTO, no principal)
        if result['sha256']:
            result['vt_result'] = self.check_virustotal(result['sha256'])
        
        # ===== FOCO PRINCIPAL: Ejecutar y detectar si AV bloquea =====
        try:
            print(f"{Colors.BLUE}Ejecutando: {file_path.name}{Colors.END}")
            start_time = time.time()
            
            # Intentar iniciar el proceso
            process = subprocess.Popen(
                str(file_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            )
            
            # Esperar un poco para ver si el AV interviene
            time.sleep(2)
            
            # Verificar si el proceso está corriendo
            # Método 1: Verificar si el proceso existe en memoria
            running = self.check_process_exists(process.pid)
            
            # Método 2: Verificar por nombre del proceso
            if not running:
                process_name = file_path.stem
                # Intentar con y sin extensión
                running = self.check_process_by_name(process_name)
            
            result['execution_time'] = time.time() - start_time
            
            if running:
                # El proceso está corriendo → El AV NO lo bloqueo
                
                result['executed'] = True
                result['running_process'] = True
                result['blocked_by_av'] = False
                result['blocked_reason'] = 'EJECUTADO'
                print(f"  {Colors.GREEN}[OK] EJECUTADO - Proceso en memoria{Colors.END}")
                print(f"    Tiempo de ejecución: {result['execution_time']:.2f}s")
            else:
                # El proceso NO está corriendo → El AV lo bloqó
                result['executed'] = False
                result['blocked'] = True
                result['blocked_by_av'] = True
                result['blocked_reason'] = 'DENEGADO'
                print(f"  {Colors.RED}[X] BLOQUEADO por Antivirus{Colors.END}")
            
            # Intentar terminar el proceso si aún está corriendo
            try:
                process.terminate()
                time.sleep(0.5)
                if process.poll() is None:
                    process.kill()
            except ProcessLookupError:
                # El proceso ya terminó
                pass
            except Exception as e:
                print(f"{Colors.YELLOW}Error terminando proceso: {e}{Colors.END}")
                
        except PermissionError as e:
            # Acceso denegado usualmente significa AV bloqueó
            result['blocked'] = True
            result['blocked_by_av'] = True
            result['error'] = f"Permiso denegado (probable bloqueo de AV): {e}"
            result['blocked_reason'] = 'PERMISO_DENEGADO'
            print(f"  {Colors.RED}[X] BLOQUEADO - Permiso denegado{Colors.END}")
            
        except FileNotFoundError as e:
            result['error'] = str(e)
            result['blocked'] = False
            result['blocked_by_av'] = False
            print(f"  {Colors.YELLOW}[!] Archivo no encontrado: {e}{Colors.END}")
            
        except OSError as e:
            # Error del sistema operativo - puede ser AV u otro problema
            error_code = getattr(e, 'winerror', None)
            if error_code in (5, 31, 32):  # Windows: Access denied, The system cannot find, Sharing violation
                result['blocked'] = True
                result['blocked_by_av'] = True
                result['error'] = f"Error SO (probable bloqueo de AV): {e}"
                result['blocked_reason'] = 'ERROR_SO'
                print(f"  {Colors.RED}[X] BLOQUEADO - Error del Sistema{Colors.END}")
            else:
                result['error'] = str(e)
                result['blocked'] = False
                result['blocked_by_av'] = False
                print(f"{Colors.YELLOW}[!] Error del sistema: {e}{Colors.END}")
            
        except Exception as e:
            # Otros errores - no asumir bloqueo de AV automáticamente
            result['error'] = str(e)
            result['blocked'] = False
            result['blocked_by_av'] = False
            print(f"{Colors.YELLOW}⚠ Error/Ejecución: {e}{Colors.END}")
        
        return result
    
    def check_process_exists(self, pid: int) -> bool:
        """Verifica si un proceso existe por PID"""
        try:
            if os.name == 'nt':
                # Windows - usar psutil si está disponible
                if psutil is not None:
                    return psutil.pid_exists(pid)
                else:
                    # Fallback: intentar usar tasklist
                    result = subprocess.run(
                        ['tasklist', '/FI', f'PID eq {pid}'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    return str(pid) in result.stdout
            else:
                # Unix
                os.kill(pid, 0)
                return True
        except (psutil.NoSuchProcess, ProcessLookupError, PermissionError) as e:
            return False
        except Exception as e:
            print(f"{Colors.YELLOW}Error verificando proceso {pid}: {e}{Colors.END}")
            return False
    
    def check_process_by_name(self, process_name: str) -> bool:
        """Verifica si hay un proceso con ese nombre"""
        try:
            if os.name == 'nt':
                result = subprocess.run(
                    ['tasklist', '/FI', f'IMAGENAME eq {process_name}.exe'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return process_name.lower() in result.stdout.lower()
            else:
                result = subprocess.run(
                    ['pgrep', '-x', process_name],
                    capture_output=True,
                    timeout=5
                )
                return result.returncode == 0
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}Timeout verificando proceso {process_name}{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.YELLOW}Error verificando proceso {process_name}: {e}{Colors.END}")
            return False
    
    def run(self) -> List[Dict]:
        """Ejecuta el analisis completo"""
        print(f"\n{'='*60}")
        print("MalTester Enhanced - Analizador de Malware")
        print(f"{'='*60}")
        print(f"\nDirectorio: {self.directory}")
        print(f"VirusTotal: {'[OK]' if self.use_virustotal else '[X]'}")
        print(f"Timeout: {self.timeout}s | Delay: {self.delay}s\n")
        
        # Buscar archivos ejecutables
        exe_files = list(self.directory.glob("*.exe"))
        self.stats['total'] = len(exe_files)
        
        if not exe_files:
            print(f"{Colors.YELLOW}No se encontraron archivos .exe en el directorio{Colors.END}")
            return []
        
        print(f"{Colors.BOLD}Archivos encontrados: {self.stats['total']}{Colors.END}")
        
        if not self.use_virustotal:
            print(f"{Colors.YELLOW}Nota: Sin API key de VirusTotal, usa --api-key o configura VT_API_KEY{Colors.END}")
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}INICIANDO ANALISIS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")
        
        for i, exe_file in enumerate(exe_files, 1):
            print(f"\n{Colors.CYAN}[{i}/{self.stats['total']}]{Colors.END} {exe_file.name}")
            print("-" * 50)
            
            # Analizar archivo
            result = self.analyze_file(exe_file)
            self.results.append(result)
            
            # Actualizar estadísticas
            if result['blocked']:
                self.stats['blocked'] += 1
            elif result['executed']:
                self.stats['passed'] += 1
            if result['error'] and not result['blocked_by_av']:
                self.stats['errors'] += 1
            if result['executed']:
                self.stats['executed'] += 1
            
            # Mostrar resultado individual
            if result['blocked_by_av']:
                print(f"  [BLOQUEADO] Antivirus detecto la muestra")
            elif result['executed']:
                print(f"  [EJECUTADO] Muestra paso el AV")
            else:
                print(f"  [ERROR] {result.get('error', 'Error desconocido')}")
            
            # Verificar VirusTotal (COMPLEMENTO)
            if result['vt_result'] and result['vt_result'].get('available'):
                vt = result['vt_result']
                if vt.get('is_malicious'):
                    print(f"  [VT] {vt.get('detection_ratio')} - MALICIOUS")
                elif vt.get('not_found'):
                    print(f"  [VT] No encontrado en DB")
                else:
                    print(f"  [VT] {vt.get('detection_ratio')} - Clean")
            
            # Mostrar estadisticas en tiempo real
            block_rate = (self.stats['blocked'] / i) * 100 if i > 0 else 0
            print(f"\n  Estadisticas tiempo real:")
            print(f"    Analizados: {i}/{self.stats['total']}")
            print(f"    Bloqueados: {self.stats['blocked']} ({block_rate:.1f}%)")
            print(f"    Ejecutados: {self.stats['passed']}")
            
            # Delay entre ejecuciones
            if i < self.stats['total']:
                time.sleep(self.delay)
        
        return self.results
    
    def print_summary(self):
        """Imprime resumen del análisis"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}RESUMEN DEL ANALISIS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        
        total = self.stats['total']
        
        print(f"\n{Colors.BOLD}Archivos analizados: {total}{Colors.END}")
        print(f"Ejecutados (NO bloqueados): {self.stats['passed']}")
        print(f"Bloqueados por AV: {self.stats['blocked']}")
        print(f"Errores: {self.stats['errors']}")
        
        if total > 0:
            block_rate = (self.stats['blocked'] / total) * 100
            pass_rate = (self.stats['passed'] / total) * 100
            
            print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}METRICAS DE EFECTIVIDAD{Colors.END}")
            print(f"{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"  Tasa de BLOQUEO:   {block_rate:6.1f}% ({self.stats['blocked']}/{total})")
            print(f"  Tasa de EJECUCION: {pass_rate:6.1f}% ({self.stats['passed']}/{total})")
        
        if self.use_virustotal:
            print(f"\n{Colors.CYAN}--- VirusTotal (referencia) ---{Colors.END}")
            print(f"Detecciones en VT: {self.stats['vt_detections']}")
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    
    def save_log(self, filename: str = "MalTesterEnhanced_log.txt"):
        """Guarda el log en archivo de texto"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"MalTester Enhanced - Log de Análisis\n")
            f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Directorio: {self.directory}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Total archivos: {self.stats['total']}\n")
            f.write(f"Bloqueados: {self.stats['blocked']}\n")
            f.write(f"Pasaron: {self.stats['passed']}\n")
            
            if self.stats['total'] > 0:
                block_rate = (self.stats['blocked'] / self.stats['total']) * 100
                f.write(f"Tasa bloqueo: {block_rate:.1f}%\n")
            
            if self.use_virustotal:
                f.write(f"VT detecciones: {self.stats['vt_detections']}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("DETALLE DE ARCHIVOS:\n")
            f.write("=" * 60 + "\n\n")
            
            for r in self.results:
                f.write(f"Archivo: {r['name']}\n")
                f.write(f"Ruta: {r['path']}\n")
                f.write(f"SHA256: {r['sha256']}\n")
                f.write(f"Estado: {'BLOQUEADO' if r['blocked'] else 'EJECUTADO/ERROR'}\n")
                
                if r['vt_result'] and r['vt_result'].get('available'):
                    if r['vt_result'].get('not_found'):
                        f.write(f"VirusTotal: No encontrado\n")
                    else:
                        f.write(f"VirusTotal: {r['vt_result'].get('detection_ratio')}\n")
                        if r['vt_result'].get('is_malicious'):
                            f.write(f"  ⚠ MALICIOUS\n")
                
                f.write("\n" + "-" * 40 + "\n\n")
        
        print(f"\n{Colors.GREEN}Log guardado en: {filename}{Colors.END}")
    
    def save_json(self, filename: str = "MalTesterEnhanced_report.json"):
        """Guarda el reporte en formato JSON"""
        report = {
            'metadata': {
                'date': datetime.now().isoformat(),
                'directory': str(self.directory),
                'total_files': self.stats['total']
            },
            'statistics': self.stats,
            'results': self.results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN}Reporte JSON guardado en: {filename}{Colors.END}")
    
    def save_csv(self, filename: str = "MalTesterEnhanced_report.csv"):
        """Guarda el reporte en formato CSV"""
        fieldnames = ['name', 'path', 'sha256', 'size', 'blocked', 'executed', 
                     'error', 'vt_malicious', 'vt_suspicious', 'vt_undetected', 'vt_detection_ratio']
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for r in self.results:
                row = {
                    'name': r['name'],
                    'path': r['path'],
                    'sha256': r['sha256'],
                    'size': r['size'],
                    'blocked': r['blocked'],
                    'executed': r['executed'],
                    'error': r['error'] or '',
                }
                
                if r['vt_result'] and r['vt_result'].get('available'):
                    row['vt_malicious'] = r['vt_result'].get('malicious', '')
                    row['vt_suspicious'] = r['vt_result'].get('suspicious', '')
                    row['vt_undetected'] = r['vt_result'].get('undetected', '')
                    row['vt_detection_ratio'] = r['vt_result'].get('detection_ratio', '')
                else:
                    row['vt_malicious'] = ''
                    row['vt_suspicious'] = ''
                    row['vt_undetected'] = ''
                    row['vt_detection_ratio'] = ''
                
                writer.writerow(row)
        
        print(f"{Colors.GREEN}Reporte CSV guardado en: {filename}{Colors.END}")


def main():
    parser = argparse.ArgumentParser(
        description='MalTester Enhanced - Analizador de Malware con VirusTotal',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('directory', nargs='?', default='.',
                       help='Directorio con archivos a analizar (default: actual)')
    parser.add_argument('--api-key', dest='api_key',
                       help='API key de VirusTotal')
    parser.add_argument('--no-virustotal', dest='no_virustotal',
                       action='store_true',
                       help='Omitir análisis de VirusTotal')
    parser.add_argument('--output', default='MalTesterEnhanced_log.txt',
                       help='Archivo de log de salida')
    parser.add_argument('--json', action='store_true',
                       help='Guardar reporte en JSON')
    parser.add_argument('--csv', action='store_true',
                       help='Guardar reporte en CSV')
    parser.add_argument('--delay', type=int, default=2,
                       help='Delay entre ejecuciones (segundos)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Timeout para ejecución de muestras')
    
    args = parser.parse_args()
    
    # Solicitar API key si no se proporciono y no se pidio omitir
    if not args.no_virustotal:
        api_key = args.api_key or os.environ.get('VT_API_KEY')
        if not api_key:
            print("\n[INFO] No se detecto API key de VirusTotal")
            print("[INFO] Ingresa tu API key (o presiona Enter para omitir):")
            api_key = input("> ").strip()
            if api_key:
                os.environ['VT_API_KEY'] = api_key
                print("[OK] API key configurada para esta sesion")
                args.api_key = api_key
            else:
                print("[INFO] VirusTotal sera omitido")
                args.no_virustotal = True
    
    # Verificar directorio
    if not os.path.isdir(args.directory):
        print(f"{Colors.RED}Error: El directorio '{args.directory}' no existe{Colors.END}")
        sys.exit(1)
    
    # Verificar permisos de lectura
    if not os.access(args.directory, os.R_OK):
        print(f"{Colors.RED}Error: No hay permisos de lectura en '{args.directory}'{Colors.END}")
        sys.exit(1)
    
    # Crear analizador
    analyzer = MalTesterEnhanced(
        directory=args.directory,
        api_key=args.api_key,
        use_virustotal=not args.no_virustotal,
        delay=args.delay,
        timeout=args.timeout
    )
    
    # Ejecutar análisis
    results = analyzer.run()
    
    # Mostrar resumen
    analyzer.print_summary()
    
    # Guardar reportes
    analyzer.save_log(args.output)
    
    if args.json:
        analyzer.save_json()
    
    if args.csv:
        analyzer.save_csv()
    
    print(f"\n{Colors.GREEN}Análisis completado{Colors.END}\n")


if __name__ == "__main__":
    main()
