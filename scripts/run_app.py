import os
import sys

os.environ["KIVY_NO_ARGS"] = "1"

sys.path.insert(0, os.path.abspath("."))
from src.mobile.main import run_mobile_app

if __name__ == "__main__":
    run_mobile_app()
