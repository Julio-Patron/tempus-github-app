#!/usr/bin/env python3
"""
Obtiene el Installation ID de la GitHub App para el operador de Tempus.
Permite autenticarse localmente con la clave privada RSA (.pem) sin exponerla a ningún servicio externo.

Uso:
    python scripts/get_installation_id.py [--pem RUTA_PEM] [--client-id CLIENT_ID]

Variables de entorno opcionales:
    GITHUB_APP_PRIVATE_KEY_PATH: Ruta al archivo .pem (por defecto: .local/github-app.pem)
    GITHUB_APP_CLIENT_ID: Client ID de la GitHub App (por defecto: Iv23liGdIKWpbivyIOA3)
"""
import argparse
import os
import sys
import time
from pathlib import Path

try:
    import jwt
    import requests
except ImportError:
    sys.exit("Error: Se requieren las dependencias 'pyjwt', 'cryptography' y 'requests'.\nInstalar con: pip install pyjwt cryptography requests")


def parse_args():
    repo_root = Path(__file__).resolve().parent.parent
    default_pem = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH") or str(repo_root / ".local" / "github-app.pem")
    default_client_id = os.environ.get("GITHUB_APP_CLIENT_ID", "Iv23liGdIKWpbivyIOA3")

    parser = argparse.ArgumentParser(description="Obtener Installation ID de GitHub App de Tempus")
    parser.add_argument(
        "--pem",
        default=default_pem,
        help="Ruta al archivo .pem con la clave privada de la GitHub App (por defecto: .local/github-app.pem)",
    )
    parser.add_argument(
        "--client-id",
        default=default_client_id,
        help="Client ID de la GitHub App",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    pem_path = Path(args.pem).expanduser().resolve()

    if not pem_path.exists():
        sys.exit(f"Error: No se encontró la clave privada RSA en: {pem_path}\nAsegúrate de especificar --pem o configurar GITHUB_APP_PRIVATE_KEY_PATH.")

    with open(pem_path, "r", encoding="utf-8") as f:
        private_key = f.read()

    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": args.client_id}
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

    print(f"Consultando instalaciones para Client ID: {args.client_id}...")
    resp = requests.get(
        "https://api.github.com/app/installations",
        headers={
            "Authorization": f"Bearer {encoded_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    resp.raise_for_status()

    installations = resp.json()
    if not installations:
        print("La App no tiene instalaciones activas todavía.")
    else:
        for inst in installations:
            print(
                f"Installation ID: {inst['id']}  |  cuenta: {inst['account']['login']}  "
                f"|  repos: {inst['repository_selection']}"
            )


if __name__ == "__main__":
    main()
