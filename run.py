import subprocess
import threading
import http.server
import os
import sys
import time
import webbrowser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_PORT = 3000
BACKEND_PORT = 3001

def run_backend():
    print(f"[Backend]  Iniciando Flask na porta {BACKEND_PORT}...")
    subprocess.run(
        [sys.executable, os.path.join(BASE_DIR, "app.py")],
        cwd=BASE_DIR
    )

def run_frontend():
    os.chdir(BASE_DIR)
    handler = http.server.SimpleHTTPRequestHandler
    handler.log_message = lambda *a: None  # silencia logs
    with http.server.HTTPServer(("", FRONTEND_PORT), handler) as httpd:
        print(f"[Frontend] Servindo na porta {FRONTEND_PORT}...")
        httpd.serve_forever()

if __name__ == "__main__":
    print("=" * 50)
    print("  ⚓  Marina One — Sistema de Gestão de Marina")
    print("=" * 50)

    t_backend = threading.Thread(target=run_backend, daemon=True)
    t_frontend = threading.Thread(target=run_frontend, daemon=True)

    t_backend.start()
    t_frontend.start()

    time.sleep(2)

    url = f"http://localhost:{FRONTEND_PORT}/frontend.html"
    print(f"\n✅ Sistema iniciado!")
    print(f"   Frontend : http://localhost:{FRONTEND_PORT}/frontend.html")
    print(f"   Backend  : http://localhost:{BACKEND_PORT}/api")
    print(f"\n   Login    : admin@marina.com / marina123")
    print("\n   Pressione Ctrl+C para encerrar.\n")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        t_backend.join()
    except KeyboardInterrupt:
        print("\nEncerrando Marina One...")
