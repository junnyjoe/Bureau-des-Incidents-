import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent

def prepare_environment():
    # Values already provided by the platform/shell win over local .env values.
    # .env is never committed. Deployment must explicitly select production settings.
    load_dotenv(ROOT / ".env", override=False)
    default = "production" if os.getenv("VERCEL") == "1" else "local"
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", f"config.settings.{default}")
