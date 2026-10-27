import os
import zipfile
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
zip_path = root_dir / "submission.zip"

files_to_add = []

# 1. Root files
for fname in ["output.csv", "README.md", "requirements.txt"]:
    fpath = root_dir / fname
    if fpath.exists():
        files_to_add.append((fpath, fname))

# 2. code/ directory files (excluding __pycache__ and .pyc)
code_dir = root_dir / "code"
for root, dirs, files in os.walk(code_dir):
    # filter out __pycache__ directories
    dirs[:] = [d for d in dirs if d != "__pycache__"]
    for f in files:
        if f.endswith((".pyc", ".pyo")):
            continue
        full_p = Path(root) / f
        rel_p = full_p.relative_to(root_dir).as_posix()
        files_to_add.append((full_p, rel_p))

print(f"Adding {len(files_to_add)} files to {zip_path.name}:")
for full_p, arcname in files_to_add:
    print(f"  {arcname}")

# Create ZIP
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for full_p, arcname in files_to_add:
        zf.write(full_p, arcname=arcname)

print(f"\nSuccessfully created {zip_path.name} (size: {zip_path.stat().st_size:,} bytes).")

# Verification
print("\n--- Verifying ZIP contents ---")
with zipfile.ZipFile(zip_path, "r") as zf:
    namelist = zf.namelist()
    print(f"Total entries in ZIP: {len(namelist)}")
    assert "output.csv" in namelist, "output.csv missing from ZIP root!"
    print("[VERIFIED] output.csv is present at the ZIP root.")
    
    # Check for excluded patterns
    for name in namelist:
        assert "__pycache__" not in name, f"Forbidden __pycache__ found: {name}"
        assert ".git" not in name, f"Forbidden .git found: {name}"
        assert "scratch" not in name, f"Forbidden scratch found: {name}"
        assert ".venv" not in name, f"Forbidden .venv found: {name}"
        assert not name.endswith(".pyc"), f"Forbidden .pyc found: {name}"
    print("[VERIFIED] All forbidden patterns (.venv, __pycache__, .git, scratch, .pyc) are excluded.")

print("[ALL VERIFICATIONS PASSED]")
