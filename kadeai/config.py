"""
KadeAI configuration loader.
Reads from .env file or environment variables.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

def load_config() -> dict:
    """Load configuration from .env file."""
    env_path = Path(__file__).parent.parent / ".env"
    load_dotenv(env_path)

    config = {
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
        "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY", ""),
        "NVD_API_KEY": os.getenv("NVD_API_KEY", ""),
        "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
        "REPORTS_DIR": os.getenv("REPORTS_DIR", "reports/"),
    }

    if not config["OPENAI_API_KEY"]:
        print("[warning] OPENAI_API_KEY not set. AI features will not work.")

    return config
