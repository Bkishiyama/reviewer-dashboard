"""
cli.py: project root entry point

Delegates to src/cli.py so the tool can be invoked as:
python cli.py <command> [options]
from the repository root.
"""
import sys
import os

# Check src/ is importable
sys.path.insert(0, os.path.dirname(__file__))

from src.cli import main

if __name__ == "__main__":
    main()
