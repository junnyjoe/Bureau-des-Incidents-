"""Create a clean course distribution; never include local credentials or runtime data."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT.parent / "output" / "incident-desk-starter.zip"
EXCLUDED_PARTS = {".git", ".venv", "__pycache__", "staticfiles", ".vercel", "htmlcov"}


def include(path):
    relative = path.relative_to(ROOT)
    if relative.as_posix() == "exercises/sql-injection/INSTRUCTOR.md":
        return False
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return False
    if path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example"):
        return False
    return path.suffix not in {".pyc", ".pyo", ".sqlite3"} and path.name not in {".DS_Store", ".coverage"}


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    files = [path for path in sorted(ROOT.rglob("*")) if path.is_file() and include(path)]
    with ZipFile(OUTPUT, "w", ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, Path("incident-desk") / path.relative_to(ROOT))
    print(f"Packaged {len(files)} files: {OUTPUT}")


if __name__ == "__main__":
    main()
