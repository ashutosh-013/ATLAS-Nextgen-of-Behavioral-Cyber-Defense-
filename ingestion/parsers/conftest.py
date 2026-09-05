import sys
from pathlib import Path

# Automatically add the parsers directory to sys.path
# so that test modules can resolve parser imports without needing custom PYTHONPATH env variables.
parsers_dir = Path(__file__).parent.resolve()
if str(parsers_dir) not in sys.path:
    sys.path.insert(0, str(parsers_dir))

# Also ensure parent directories are accessible if needed
parent_dir = parsers_dir.parent.parent.resolve()
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))
