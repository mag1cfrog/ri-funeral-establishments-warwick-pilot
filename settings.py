import os
try:
    from dotenv import load_dotenv  # pip install python-dotenv
    load_dotenv()  # loads .env if present
except Exception:
    pass

GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")