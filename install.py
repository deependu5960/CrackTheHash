import subprocess
import sys

print("Installing dependencies...")

subprocess.call([
    sys.executable,
    "-m",
    "pip",
    "install",
    "-r",
    "requirements.txt",
    "--break-system-packages"
])

print("Done. Run: python start.py")