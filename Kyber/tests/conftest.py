import sys
from pathlib import Path

# pytest をどこから実行しても `import Kyber` が通るようにする
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
