#!/usr/bin/env python3
"""
MalTester URL Analyzer - Analizador de URLs maliciosas
Características:
- Análisis de URLs contra servicios de reputación (VirusTotal, URLVoid, PhishTank)
- Descarga de muestras y verificación de detección por AV local
- Estadísticas detalladas de bloqueo
- Reportes en JSON y CSV

Uso: python MalTesterURL.py [archivo_urls] [opciones]

Opciones:
  --api-key       API key de VirusTotal (o configurar en variable de entorno VT_API_KEY)
  --urlvoid-key   API key de URLVoid (o configurar en variable de entorno URLVOID_API_KEY)
  --no-download   No descargar archivos, solo analizar URLs
  --output        Archivo de salida (default: MalTesterURL_log.txt)
  --json          Guardar reporte en formato JSON
  --csv           Guardar reporte en formato CSV
  --delay         Delay entre análisis en segundos (default: 3)
  --timeout       Timeout para descargas (default: 30)
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
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

# Configuración de APIs
VT_API_URL = "https://www.virustotal.com/api/v3"
URLVOID_API_URL = "https://api.urlvoid.com/api100"
VT_HEADERS = {"Accept": "application/json"}

# Intentar importar psutil para verificación de procesos
try:
    import psutil
except ImportError:
    psutil = None
    print(f"[WARNING] psutil no está instalado. La verificación de procesos será limitada.")


class Colors:
    """Colores para terminal"""
    GREEN = ''
    RED = ''
    YELLOW = ''
    BLUE = ''
    CYAN = ''
    BOLD = ''
    END = ''


class MalTesterURL:
    """Clase principal del analizador de URLs"""
    
    def __init__(self, api_key: Optional[str] = None, urlvoid_key: Optional[str] = None,
                 download_files: bool = True, delay: int = 3, timeout: int = 30):
        self.api_key = api_key or os.environ.get('VT_API_KEY')
        self.urlvoid_key = urlvoid_key or os.environ.get('URLVOID_API_KEY')
        self.download_files = download_files
        self.delay = delay
        self.timeout = timeout
        
        # Resultados
        self.results: List[Dict] = []
        self.stats = {
            'total': 0,
            'analyzed': 0,
            'malicious': 0,
            'suspicious': 0,
            'clean': 0,
            'blocked_by_av': 0,
            'download_failed': 0,
            'errors': 0
        }
        
        # Directorio temporal para descargas
        self.temp_dir = Path("MalTesterURL_downloads")
        self.temp_dir.mkdir(exist_ok=True)
    
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
    
    def check_virustotal_url(self, url: str) -> Dict:
        """Envía URL a VirusTotal para análisis"""
        if not self.api_key:
            return {'available': False, 'error': 'Sin API key'}
        
        try:
            # VirusTotal v3 - Analyze URL
            url_analyze = f"{VT_API_URL}/urls"
            headers = {"x-apikey": self.api_key, **VT_HEADERS}
            data = {"url": url}
            
            response = requests.post(url_analyze, headers=headers, data=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get('data', {}).get('id')
                
                if analysis_id:
                    # Esperar un poco y obtener resultados
                    time.sleep(2)
                    return self._get_vt_analysis(analysis_id)
                    
            elif response.status_code == 429:
                return {'available': False, 'error': 'Rate limited'}
            
        except Exception as e:
            return {'available': False, 'error': str(e)}
        
        return {'available': False, 'error': 'Unknown error'}
    
    def _get_vt_analysis(self, analysis_id: str) -> Dict:
        """Obtiene resultados de análisis de VirusTotal"""
        try:
            url_analysis = f"{VT_API_URL}/analyses/{analysis_id}"
            headers = {"x-apikey": self.api_key, **VT_HEADERS}
            
            response = requests.get(url_analysis, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                return {
                    'available': True,
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'undetected': stats.get('undetected', 0),
                    'total_engines': total,
                    'detection_ratio': f"{malicious + suspicious}/{total}",
                    'is_malicious': malicious > 0 or suspicious > 0
                }
        except Exception as e:
            return {'available': False, 'error': str(e)}
        
        return {'available': False}
    
    def check_virustotal_hash(self, file_hash: str) -> Dict:
        """Consulta hash en VirusTotal"""
        if not self.api_key:
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
    
    def check_urlvoid(self, url: str) -> Dict:
        """Analiza URL usando URLVoid"""
        if not self.urlvoid_key:
            return {'available': False}
        
        try:
            api_url = f"{URLVOID_API_URL}/{self.urlvoid_key}/host/{url}"
            response = requests.get(api_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                detection = data.get('detection', {})
                
                return {
                    'available': True,
                    'engines': detection.get('engines', 0),
                    'detection_ratio': detection.get('detections', '0/0'),
                    'is_malicious': detection.get('engines', 0) > 0
                }
        except Exception as e:
            return {'available': False, 'error': str(e)}
        
        return {'available': False}
    
    def download_file(self, url: str) -> Optional[Path]:
        """Descarga un archivo desde una URL"""
        try:
            print(f"{Colors.CYAN}  Descargando: {url[:60]}...{Colors.END}")
            
            response = requests.get(url, timeout=self.timeout, stream=True)
            response.raise_for_status()
            
            # Extraer nombre de archivo de la URL
            parsed = urlparse(url)
            filename = Path(parsed.path).name
            
            if not filename or '.' not in filename:
                # Generar nombre basado en hash
                content_hash = hashlib.md5(url.encode()).hexdigest()[:8]
                filename = f"sample_{content_hash}.bin"
            
            filepath = self.temp_dir / filename
            
            # Guardar archivo
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print(f"{Colors.GREEN}  [OK] Descargado: {filepath.name}{Colors.END}")
            return filepath
            
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}  [X] Timeout al descargar{Colors.END}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}  [X] Error de descarga: {e}{Colors.END}")
            return None
        except Exception as e:
            print(f"{Colors.RED}  [X] Error: {e}{Colors.END}")
            return None
    
    def check_av_blocks_download(self, file_path: Path) -> bool:
        """Verifica si el AV local bloquea el archivo descargado"""
        try:
            # Intentar ejecutar el archivo y verificar si el AV lo bloquea
            print(f"{Colors.CYAN}  Verificando si AV bloquea el archivo...{Colors.END}")
            
            process = subprocess.Popen(
                str(file_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            )
            
            # Esperar un poco para ver si el AV interviene
            time.sleep(2)
            
            # Verificar si el proceso está corriendo
            blocked = True
            if os.name == 'nt' and psutil:
                blocked = not psutil.pid_exists(process.pid)
            else:
                # Método alternativo
                try:
                    os.kill(process.pid, 0)
                    blocked = False
                except:
                    blocked = True
            
            # Intentar terminar el proceso
            try:
                process.terminate()
                time.sleep(0.5)
                if process.poll() is None:
                    process.kill()
            except:
                pass
            
            return blocked
            
        except PermissionError:
            # Acceso denegado = AV bloqueó
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"{Colors.YELLOW}  [!] Error verificando: {e}{Colors.END}")
            return False
    
    def analyze_url(self, url: str) -> Dict:
        """Analiza una URL individual"""
        result = {
            'url': url,
            'domain': urlparse(url).netloc if urlparse(url).netloc else url,
            'vt_result': None,
            'urlvoid_result': None,
            'downloaded_file': None,
            'file_hash': None,
            'blocked_by_av': False,
            'is_malicious': False,
            'error': None,
            'analysis_time': 0
        }
        
        start_time = time.time()
        
        # Validar URL
        parsed = urlparse(url)
        if not parsed.scheme:
            result['error'] = 'URL inválida (sin esquema)'
            return result
        
        # Análisis con VirusTotal
        if self.api_key:
            print(f"{Colors.BLUE}  Consultando VirusTotal...{Colors.END}")
            result['vt_result'] = self.check_virustotal_url(url)
            if result['vt_result'].get('available'):
                if result['vt_result'].get('is_malicious'):
                    result['is_malicious'] = True
        
        # Análisis con URLVoid
        if self.urlvoid_key:
            print(f"{Colors.BLUE}  Consultando URLVoid...{Colors.END}")
            result['urlvoid_result'] = self.check_urlvoid(url)
            if result['urlvoid_result'].get('available'):
                if result['urlvoid_result'].get('is_malicious'):
                    result['is_malicious'] = True
        
        # Descargar archivo si está habilitado
        if self.download_files:
            downloaded = self.download_file(url)
            if downloaded:
                result['downloaded_file'] = str(downloaded)
                result['file_hash'] = self.calculate_hash(downloaded)
                
                # Verificar hash en VirusTotal
                if result['file_hash'] and self.api_key:
                    print(f"{Colors.BLUE}  Verificando hash en VirusTotal...{Colors.END}")
                    vt_hash_result = self.check_virustotal_hash(result['file_hash'])
                    if vt_hash_result.get('available') and not vt_hash_result.get('not_found'):
                        result['vt_hash_result'] = vt_hash_result
                        if vt_hash_result.get('is_malicious'):
                            result['is_malicious'] = True
                
                # Verificar si AV bloquea
                print(f"{Colors.BLUE}  Verificando bloqueo del AV local...{Colors.END}")
                result['blocked_by_av'] = self.check_av_blocks_download(downloaded)
        
        result['analysis_time'] = time.time() - start_time
        return result
    
    def load_urls_from_file(self, filepath: str) -> List[str]:
        """Carga URLs desde un archivo"""
        urls = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Ignorar comentarios y líneas vacías
                    if line and not line.startswith('#'):
                        # Validar que sea una URL
                        if line.startswith(('http://', 'https://', 'ftp://')):
                            urls.append(line)
                        else:
                            # Agregar esquema si no tiene
                            urls.append(f"https://{line}")
        except FileNotFoundError:
            print(f"{Colors.RED}Error: Archivo no encontrado: {filepath}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}Error leyendo archivo: {e}{Colors.END}")
        
        return urls
    
    def run(self, urls: List[str]) -> List[Dict]:
        """Ejecuta el análisis completo"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}MalTester URL Analyzer - Analizador de URLs Maliciosas{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"\nURLs a analizar: {len(urls)}")
        print(f"VirusTotal: {'[OK]' if self.api_key else '[X]'}")
        print(f"URLVoid: {'[OK]' if self.urlvoid_key else '[X]'}")
        print(f"Descarga de archivos: {'[OK]' if self.download_files else '[X]'}")
        
        if not self.api_key and not self.urlvoid_key:
            print(f"\n{Colors.YELLOW}Advertencia: Sin API keys, solo se intentará descargar archivos{Colors.END}")
        
        print(f"\n{Colors.BOLD}Iniciando análisis...{Colors.END}\n")
        
        self.stats['total'] = len(urls)
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{self.stats['total']}] Analizando: {url[:50]}...")
            
            # Analizar URL
            result = self.analyze_url(url)
            self.results.append(result)
            
            # Actualizar estadísticas
            self.stats['analyzed'] += 1
            
            if result['error']:
                self.stats['errors'] += 1
                print(f"  {Colors.YELLOW}⚠ Error: {result['error']}{Colors.END}")
                continue
            
            if result['is_malicious']:
                if result.get('vt_result', {}).get('malicious', 0) > 0:
                    self.stats['malicious'] += 1
                elif result.get('vt_result', {}).get('suspicious', 0) > 0:
                    self.stats['suspicious'] += 1
                elif result.get('urlvoid_result', {}).get('is_malicious'):
                    self.stats['malicious'] += 1
            else:
                self.stats['clean'] += 1
            
            if result['blocked_by_av']:
                self.stats['blocked_by_av'] += 1
                print(f"  {Colors.RED}[X] BLOQUEADO por AV local{Colors.END}")
            
            if result['downloaded_file'] and not result['blocked_by_av']:
                print(f"  {Colors.GREEN}[OK] Descargado y no bloqueado{Colors.END}")
            
            # Mostrar resultados de análisis
            if result['vt_result'] and result['vt_result'].get('available'):
                vt = result['vt_result']
                if vt.get('is_malicious'):
                    print(f"  {Colors.RED}VT: {vt.get('detection_ratio')} - MALICIOUS{Colors.END}")
                else:
                    print(f"  {Colors.GREEN}VT: {vt.get('detection_ratio')} - Clean{Colors.END}")
            
            if result['urlvoid_result'] and result['urlvoid_result'].get('available'):
                uv = result['urlvoid_result']
                if uv.get('is_malicious'):
                    print(f"  {Colors.RED}URLVoid: {uv.get('detection_ratio')} - DETECTED{Colors.END}")
                else:
                    print(f"  {Colors.GREEN}URLVoid: Clean{Colors.END}")
            
            # Delay entre análisis
            if i < self.stats['total']:
                time.sleep(self.delay)
        
        return self.results
    
    def print_summary(self):
        """Imprime resumen del análisis"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}RESUMEN DEL ANÁLISIS - ESTADÍSTICAS{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")
        
        total = self.stats['total']
        
        print(f"\n{Colors.BOLD}URLs analizadas: {total}{Colors.END}")
        print(f"Maliciosas detectadas: {self.stats['malicious']}")
        print(f"Sospechosas: {self.stats['suspicious']}")
        print(f"Limpias: {self.stats['clean']}")
        
        if total > 0:
            malicious_rate = ((self.stats['malicious'] + self.stats['suspicious']) / total) * 100
            clean_rate = (self.stats['clean'] / total) * 100
            
            print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}RESUMEN DE BLOQUEO{Colors.END}")
            print(f"{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"Tasa de DETECCIÓN: {malicious_rate:.1f}%")
            print(f"Tasa LIMPIAS: {clean_rate:.1f}%")
        
        if self.stats['blocked_by_av'] > 0:
            print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}BLOQUEOS POR ANTIVIRUS LOCAL{Colors.END}")
            print(f"{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"Archivos bloqueados: {self.stats['blocked_by_av']}")
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    
    def cleanup(self):
        """Limpia archivos temporales"""
        try:
            if self.temp_dir.exists():
                import shutil
                shutil.rmtree(self.temp_dir)
                print(f"{Colors.CYAN}Archivos temporales eliminados{Colors.END}")
        except Exception as e:
            print(f"{Colors.YELLOW}Error limpiando archivos: {e}{Colors.END}")
    
    def save_log(self, filename: str = "MalTesterURL_log.txt"):
        """Guarda el log en archivo de texto"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"MalTester URL Analyzer - Log de Análisis\n")
            f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Total URLs: {self.stats['total']}\n")
            f.write(f"Maliciosas: {self.stats['malicious']}\n")
            f.write(f"Sospechosas: {self.stats['suspicious']}\n")
            f.write(f"Limpias: {self.stats['clean']}\n")
            f.write(f"Bloqueadas por AV: {self.stats['blocked_by_av']}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("DETALLE DE URLs:\n")
            f.write("=" * 60 + "\n\n")
            
            for r in self.results:
                f.write(f"URL: {r['url']}\n")
                f.write(f"Dominio: {r.get('domain', 'N/A')}\n")
                
                if r.get('vt_result') and r['vt_result'].get('available'):
                    f.write(f"VirusTotal: {r['vt_result'].get('detection_ratio', 'N/A')}\n")
                
                if r.get('urlvoid_result') and r['urlvoid_result'].get('available'):
                    uv = r['urlvoid_result']
                    f.write(f"URLVoid: {uv.get('detection_ratio', 'N/A')}\n")
                
                if r.get('downloaded_file'):
                    f.write(f"Archivo: {r['downloaded_file']}\n")
                    f.write(f"Hash: {r.get('file_hash', 'N/A')}\n")
                
                if r['blocked_by_av']:
                    f.write(f"Estado: BLOQUEADO POR AV\n")
                elif r['is_malicious']:
                    f.write(f"Estado: MALICIOSA (detectada por servicios)\n")
                else:
                    f.write(f"Estado: LIMPIA\n")
                
                f.write("\n" + "-" * 40 + "\n\n")
        
        print(f"\n{Colors.GREEN}Log guardado en: {filename}{Colors.END}")
    
    def save_json(self, filename: str = "MalTesterURL_report.json"):
        """Guarda el reporte en formato JSON"""
        report = {
            'metadata': {
                'date': datetime.now().isoformat(),
                'total_urls': self.stats['total'],
                'api_keys_configured': {
                    'virustotal': bool(self.api_key),
                    'urlvoid': bool(self.urlvoid_key)
                }
            },
            'statistics': self.stats,
            'results': self.results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN}Reporte JSON guardado en: {filename}{Colors.END}")
    
    def save_csv(self, filename: str = "MalTesterURL_report.csv"):
        """Guarda el reporte en formato CSV"""
        fieldnames = ['url', 'domain', 'is_malicious', 'vt_malicious', 'vt_suspicious', 
                     'vt_detection_ratio', 'urlvoid_detections', 'downloaded_file', 
                     'file_hash', 'blocked_by_av', 'analysis_time']
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for r in self.results:
                row = {
                    'url': r['url'],
                    'domain': r.get('domain', ''),
                    'is_malicious': r['is_malicious'],
                    'downloaded_file': r.get('downloaded_file', ''),
                    'file_hash': r.get('file_hash', ''),
                    'blocked_by_av': r['blocked_by_av'],
                    'analysis_time': round(r.get('analysis_time', 0), 2)
                }
                
                if r.get('vt_result') and r['vt_result'].get('available'):
                    row['vt_malicious'] = r['vt_result'].get('malicious', '')
                    row['vt_suspicious'] = r['vt_result'].get('suspicious', '')
                    row['vt_detection_ratio'] = r['vt_result'].get('detection_ratio', '')
                else:
                    row['vt_malicious'] = ''
                    row['vt_suspicious'] = ''
                    row['vt_detection_ratio'] = ''
                
                if r.get('urlvoid_result') and r['urlvoid_result'].get('available'):
                    row['urlvoid_detections'] = r['urlvoid_result'].get('engines', '')
                else:
                    row['urlvoid_detections'] = ''
                
                writer.writerow(row)
        
        print(f"{Colors.GREEN}Reporte CSV guardado en: {filename}{Colors.END}")


def main():
    print(f"\n{'='*60}")
    print("MalTester URL Analyzer")
    print(f"{'='*60}\n")
    
    parser = argparse.ArgumentParser(
        description='MalTester URL Analyzer - Analizador de URLs con VirusTotal y URLVoid',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('urls_file', nargs='?', default='urls.txt',
                       help='Archivo con lista de URLs (default: urls.txt)')
    parser.add_argument('--api-key', dest='api_key',
                       help='API key de VirusTotal')
    parser.add_argument('--urlvoid-key', dest='urlvoid_key',
                       help='API key de URLVoid')
    parser.add_argument('--no-download', dest='no_download',
                       action='store_true',
                       help='No descargar archivos, solo analizar URLs')
    parser.add_argument('--output', default='MalTesterURL_log.txt',
                       help='Archivo de log de salida')
    parser.add_argument('--json', action='store_true',
                       help='Guardar reporte en JSON')
    parser.add_argument('--csv', action='store_true',
                       help='Guardar reporte en CSV')
    parser.add_argument('--delay', type=int, default=3,
                       help='Delay entre analisis (segundos)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Timeout para descargas (segundos)')
    parser.add_argument('--url', dest='single_url',
                       help='Analizar una URL individual')
    
    args = parser.parse_args()
    
    # Cargar URLs
    urls = []
    
    if args.single_url:
        urls = [args.single_url]
        print(f"URL a analizar: {urls[0]}\n")
    else:
        # Intentar cargar desde archivo
        if os.path.isfile(args.urls_file):
            print(f"Cargando URLs desde: {args.urls_file}")
            urls = MalTesterURL().load_urls_from_file(args.urls_file)
        else:
            # Crear archivo de ejemplo
            print(f"[WARNING] Archivo '{args.urls_file}' no encontrado.")
            print(f"[INFO] Creando archivo de ejemplo...")
            try:
                with open(args.urls_file, 'w', encoding='utf-8') as f:
                    f.write("# Lista de URLs para analizar\n")
                    f.write("# Formato: una URL por linea\n")
                    f.write("# Las lineas que comienzan con # son comentarios\n")
                    f.write("\n# Ejemplos:\n")
                    f.write("# https://example.com/malware.exe\n")
                    f.write("# http://suspicious-site.com/payload.exe\n")
                print(f"[OK] Archivo '{args.urls_file}' creado.")
                print(f"[INFO] Agrega tus URLs y ejecuta nuevamente.")
            except Exception as e:
                print(f"[ERROR] No se pudo crear el archivo: {e}")
            print("\nPresiona Enter para salir...")
            input()
            return
    
    if not urls:
        print(f"[ERROR] No se encontraron URLs para analizar")
        print("\nPresiona Enter para salir...")
        input()
        return
    
    print(f"URLs cargadas: {len(urls)}\n")
    
    # Crear analizador
    analyzer = MalTesterURL(
        api_key=args.api_key,
        urlvoid_key=args.urlvoid_key,
        download_files=not args.no_download,
        delay=args.delay,
        timeout=args.timeout
    )
    
    # Ejecutar analisis
    results = analyzer.run(urls)
    
    # Mostrar resumen
    analyzer.print_summary()
    
    # Guardar reportes
    analyzer.save_log(args.output)
    
    if args.json:
        analyzer.save_json()
    
    if args.csv:
        analyzer.save_csv()
    
    # Limpiar archivos temporales
    analyzer.cleanup()
    
    print(f"\n[OK] Analisis completado\n")
    print("Presiona Enter para salir...")
    input()


if __name__ == "__main__":
    main()
