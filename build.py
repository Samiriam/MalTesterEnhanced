#!/usr/bin/env python3
"""
Script de compilación para MalTester
Crea ejecutables independientes de MalTester Enhanced y MalTesterURL

Uso: python build.py [opciones]

Opciones:
  --enhanced-only   Solo compilar MalTesterEnhanced
  --url-only        Solo compilar MalTesterURL
  --all            Compilar ambos (default)
  --clean           Limpiar archivos de compilación previos
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# Configuración
SCRIPT_DIR = Path(__file__).parent
DIST_DIR = SCRIPT_DIR / "dist"
BUILD_DIR = SCRIPT_DIR / "build"

# Obtener la ruta del Scripts del entorno virtual
VENV_DIR = SCRIPT_DIR / ".venv"
PYINSTALLER_BIN = VENV_DIR / "Scripts" / "pyinstaller.exe"
PYTHON_BIN = VENV_DIR / "Scripts" / "python.exe"

# Archivos principales
MAIN_FILES = {
    "MalTesterEnhanced": "MalTesterEnhanced.py",
    "MalTesterURL": "MalTesterURL.py"
}

# Icono (opcional - crear uno simple si no existe)
ICON_FILE = SCRIPT_DIR / "icon.ico"


def check_dependencies():
    """Verifica que PyInstaller esté instalado"""
    try:
        import PyInstaller
        print(f"[OK] PyInstaller instalado: {PyInstaller.__version__}")
        return True
    except ImportError:
        print("[ERROR] PyInstaller no está instalado")
        print("  Instalar con: pip install pyinstaller")
        return False


def clean_build():
    """Limpia archivos de compilación anteriores"""
    print("\n[1/4] Limpiando compilación anterior...")
    
    folders_to_clean = [
        DIST_DIR,
        BUILD_DIR,
        SCRIPT_DIR / "build",
    ]
    
    for folder in folders_to_clean:
        if folder.exists():
            shutil.rmtree(folder)
            print(f"  [X] Eliminado: {folder}")
    
    # Limpiar archivos .spec
    for spec_file in SCRIPT_DIR.glob("*.spec"):
        spec_file.unlink()
        print(f"  [X] Eliminado: {spec_file}")
    
    print("  Limpieza completada")


def build_executable(name, script_file, console=True):
    """Compila un script Python a ejecutable"""
    print(f"\n[2/4] Compilando {name}...")
    
    # Argumentos base de PyInstaller
    args = [
        str(PYINSTALLER_BIN),
        "--name", name,
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR),
        "--specpath", str(SCRIPT_DIR),
    ]
    
    # Tipo de ventana
    if not console:
        args.append("--noconsole")
    else:
        args.append("--console")
    
    # One-file (ejecutable único)
    args.append("--onefile")
    
    # Añadir archivo principal
    args.append(str(SCRIPT_DIR / script_file))
    
    # Limpiar archivos de compilación específicos
    spec_file = SCRIPT_DIR / f"{name}.spec"
    if spec_file.exists():
        spec_file.unlink()
    
    print(f"  Ejecutando: {' '.join(args)}")
    
    try:
        result = subprocess.run(args, check=True, capture_output=True, text=True)
        print(f"  [OK] {name} compilado exitosamente")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Error compilando {name}")
        print(f"    {e.stderr}")
        return False


def copy_dependencies():
    """Copia archivos adicionales necesarios"""
    print("\n[3/4] Copiando archivos adicionales...")
    
    if not DIST_DIR.exists():
        print("  [!] No hay carpeta dist, omitiendo")
        return
    
    # Copiar archivos de ejemplo si existen
    example_files = [
        "urls.txt",
        "README.txt",
        "requirements.txt"
    ]
    
    for filename in example_files:
        src = SCRIPT_DIR / filename
        if src.exists():
            dst = DIST_DIR / filename
            shutil.copy2(src, dst)
            print(f"  [OK] Copiado: {filename}")
    
    print("  Archivos adicionales copiados")


def print_summary():
    """Muestra resumen de la compilación"""
    print("\n[4/4] Resumen de compilación")
    print("=" * 50)
    
    if DIST_DIR.exists():
        exe_files = list(DIST_DIR.glob("*.exe"))
        print(f"\nEjecutables creados:")
        for exe in exe_files:
            size_mb = exe.stat().st_size / (1024 * 1024)
            print(f"  * {exe.name} ({size_mb:.1f} MB)")
        
        print(f"\nUbicación: {DIST_DIR.absolute()}")
    else:
        print("[!] No se crearon ejecutables")
    
    print("\n" + "=" * 50)
    print("Compilación completada!")


def main():
    print("=" * 50)
    print("MalTester Build Script")
    print("=" * 50)
    
    # Parsear argumentos
    args = sys.argv[1:]
    
    enhanced_only = "--enhanced-only" in args
    url_only = "--url-only" in args
    clean = "--clean" in args
    
    # Verificar PyInstaller
    if not check_dependencies():
        sys.exit(1)
    
    # Limpiar si se solicita
    if clean:
        clean_build()
    
    # Determinar qué compilar
    build_enhanced = not url_only
    build_url = not enhanced_only
    
    # Compilar
    if build_enhanced:
        build_executable("MalTesterEnhanced", "MalTesterEnhanced.py")
    
    if build_url:
        build_executable("MalTesterURL", "MalTesterURL.py")
    
    # Copiar dependencias
    copy_dependencies()
    
    # Mostrar resumen
    print_summary()


if __name__ == "__main__":
    main()
