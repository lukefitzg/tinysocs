import os
from pathlib import Path


def load_dotenv_if_present(repo_root: Path | None = None) -> None:
    """
    Minimal .env loader that never overwrites existing environment variables.
    Looks for a file named '.env' in repo_root (if provided) or the CWD.
    Lines starting with '#' are ignored. Values may be quoted.
    """
    root = repo_root or Path.cwd()
    env_path = root / ".env"
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v
