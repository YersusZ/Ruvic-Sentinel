"""Alias de desarrollo del agente.

El binario y Docker usan `ws_tools_client_embedded.py`. Este archivo existe
para no romper `python ws_tools_client.py --url …` en lab: mismo `main()`,
incluido `--url`.
"""

from ws_tools_client_embedded import main

if __name__ == "__main__":
    main()
