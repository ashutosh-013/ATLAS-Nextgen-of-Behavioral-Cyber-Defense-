"""
ATLAS Desktop Build & Packaging Automation Pipeline
---------------------------------------------------
Automates:
1. Environment and dependency validation (auto-installs PyInstaller & pywebview if missing).
2. Application icon generation (.ico) with multi-resolution scaling.
3. PyInstaller compilation with UAC elevation into dist/ATLAS/.
4. Optional Inno Setup compilation into a standalone Windows installer (Setup.exe).
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path


def print_step(title: str):
    print("\n" + "=" * 80)
    print(f" [ATLAS BUILD] {title}")
    print("=" * 80)


def ensure_dependencies():
    """Verify and automatically install required packaging packages."""
    print_step("Checking Build Dependencies")
    required_packages = ["pyinstaller", "pillow"]
    optional_packages = ["pywebview"]

    for pkg in required_packages + optional_packages:
        try:
            __import__(pkg)
            print(f"  [OK] {pkg} is installed.")
        except ImportError:
            print(f"  [+] Installing missing library: {pkg}...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                    stdout=subprocess.DEVNULL
                )
                print(f"  [OK] Successfully installed {pkg}.")
            except Exception as e:
                if pkg in required_packages:
                    print(f"  [!] Failed to install critical dependency '{pkg}': {e}")
                    sys.exit(1)
                else:
                    print(f"  [-] Optional package '{pkg}' could not be installed; falling back to Edge App Mode.")


def generate_app_icon():
    """Generate high-resolution Windows .ico file from brand logo."""
    print_step("Generating High-Resolution Windows Icon")
    from PIL import Image

    src_jpg = Path("frontend") / "atlas_logo.jpg"
    dest_ico = Path("frontend") / "atlas_logo.ico"

    if not src_jpg.exists():
        print(f"  [!] Error: Brand logo source not found at {src_jpg}")
        sys.exit(1)

    try:
        img = Image.open(src_jpg)
        sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        img.save(dest_ico, format="ICO", sizes=sizes)
        print(f"  [OK] Generated multi-resolution Windows icon at: {dest_ico}")
    except Exception as e:
        print(f"  [!] Failed to generate icon: {e}")
        sys.exit(1)


def run_pyinstaller_build():
    """Compile application into dist/ATLAS/ using atlas_desktop.spec."""
    print_step("Compiling Standalone Desktop Application with PyInstaller")
    spec_file = Path("atlas_desktop.spec")

    if not spec_file.exists():
        print(f"  [!] Error: Specification file {spec_file} missing.")
        sys.exit(1)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        str(spec_file),
        "--clean",
        "-y"
    ]

    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)

    if result.returncode != 0:
        print(f"\n  [!] PyInstaller build failed with exit code: {result.returncode}")
        sys.exit(result.returncode)

    output_exe = Path("dist") / "ATLAS" / "ATLAS.exe"
    if output_exe.exists():
        size_mb = output_exe.stat().st_size / (1024 * 1024)
        print(f"\n  [SUCCESS] PyInstaller compilation completed!")
        print(f"  Application Location: {output_exe.resolve()}")
        print(f"  Main Executable Size: {size_mb:.2f} MB")
    else:
        print(f"  [!] Warning: Expected output {output_exe} not found.")

    # Ensure frontend and knowledge_base exist directly in dist/ATLAS as well as _internal
    dist_dir = Path("dist") / "ATLAS"
    if dist_dir.exists():
        for asset in ["frontend", "knowledge_base"]:
            src = Path(asset)
            dst = dist_dir / asset
            if src.exists():
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
                print(f"  [OK] Synced {asset}/ into {dst}")
        if Path("config.json").exists():
            shutil.copy("config.json", dist_dir / "config.json")



def build_inno_setup_installer():
    """Locate Inno Setup compiler and compile setup wizard if installed."""
    print_step("Checking for Inno Setup Compiler (Installer Creation)")
    iss_file = Path("atlas_setup.iss")
    if not iss_file.exists():
        print("  [-] atlas_setup.iss not found, skipping installer build.")
        return

    # Check common Inno Setup 6 installations
    possible_iscc = [
        shutil.which("iscc"),
        shutil.which("iscc.exe"),
        os.path.expandvars(r"%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"),
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
        r"C:\Program Files (x86)\Inno Setup 5\ISCC.exe",
    ]

    iscc_path = None
    for p in possible_iscc:
        if p and Path(p).exists():
            iscc_path = p
            break

    if iscc_path:
        print(f"  Found Inno Setup compiler at: {iscc_path}")
        print("  Compiling professional Windows setup wizard...")
        cmd = [iscc_path, str(iss_file)]
        res = subprocess.run(cmd)
        if res.returncode == 0:
            installer_path = Path("dist_installer") / "ATLAS_v2.5_Enterprise_Setup.exe"
            print(f"\n  [SUCCESS] Installer built successfully at: {installer_path.resolve()}")
        else:
            print("  [!] Inno Setup compilation encountered an issue.")
    else:
        print("  [INFO] Inno Setup is not installed on this machine.")
        print("  The standalone desktop application is already fully runnable at: dist/ATLAS/ATLAS.exe")
        print("\n  To generate a single Setup.exe installer in the future:")
        print("  1. Run: winget install JRSoftware.InnoSetup")
        print("  2. Or download free from: https://jrsoftware.org/isdl.php")
        print("  3. Then re-run: python build_desktop_app.py")


def main():
    print("================================================================================")
    print("       ATLAS BEHAVIORAL CYBER DEFENSE - PACKAGING AUTOMATION")
    print("================================================================================")
    ensure_dependencies()
    generate_app_icon()
    run_pyinstaller_build()
    build_inno_setup_installer()
    print_step("Build Finished")
    print("  You can now run: .\\dist\\ATLAS\\ATLAS.exe")
    print("================================================================================\n")


if __name__ == "__main__":
    main()
