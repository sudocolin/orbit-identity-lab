"""Creates .env from .env.example and fills in random SCIM_TOKEN and SESSION_SECRET.

Never prints the secrets, so it's safe to run while recording.
"""
import secrets
from pathlib import Path

here = Path(__file__).parent
env = here / ".env"
if not env.exists():
    env.write_text((here / ".env.example").read_text())

lines, filled = [], []
for line in env.read_text().splitlines():
    key, _, value = line.partition("=")
    if key in ("SCIM_TOKEN", "SESSION_SECRET") and not value.strip():
        line = f"{key}={secrets.token_urlsafe(48)}"
        filled.append(key)
    lines.append(line)
env.write_text("\n".join(lines) + "\n")
print(f".env ready ({', '.join(filled) or 'secrets already set'}). Open it to fill in the Entra values.")
