"""Valida todos os módulos ofensivos contra um servidor local (autorizado)."""
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, TRACE, OPTIONS")
        self.end_headers()

    def do_TRACE(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"TRACE OK")

    def do_POST(self):
        if self.path.startswith("/login"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode() if length else ""
            from urllib.parse import parse_qs
            data = parse_qs(body)
            user = data.get("username", [""])[0]
            pwd = data.get("password", [""])[0]
            if user == "admin" and pwd == "admin":
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.end_headers()
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"login invalido")
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/users"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"users":[{"id":1}]}')
        elif self.path.startswith("/user?"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"perfil do usuario (id variado)" * 3)
        elif self.path.startswith("/rate"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path.startswith("/cors"):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b'{"data": 1}')
        elif self.path.startswith("/method"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path.startswith("/file"):
            # simula LFI quando o param file contém passwd
            if "passwd" in self.path:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"root:x:0:0:root:/root:/bin/bash\n")
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
        elif self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "https://evil.example.com/steal")
            self.end_headers()
        elif self.path.startswith("/sqli"):
            # simula erro de banco quando o payload contém aspa (quebra de query)
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            val = qs.get("id", [""])[0]
            if "'" in val or '\"' in val:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"You have an error in your SQL syntax; check the manual")
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
        elif self.path.startswith("/xss"):
            # reflete o valor do param q sem encoding (XSS)
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            val = qs.get("q", [""])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"<html><body>{val}</body></html>".encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")


server = HTTPServer(("127.0.0.1", 0), Handler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

base = f"http://127.0.0.1:{port}"
print(f"[INFO] Servidor local de teste na porta {port}")

from src.core.attack.engine import run_attack_modules, MODULE_LABELS
from src.core.attack.recon_active import active_recon

# Recon ativo contra o próprio servidor
ports = active_recon("127.0.0.1", ports=[(port, "HTTP-test")], timeout=2)
assert any(p["porta"] == port for p in ports), "recon não achou a porta"
print("[OK] Recon ativo: porta detectada")

# Engine completo com TODOS os módulos
url_cors = f"{base}/cors"
url_method = f"{base}/method"
url_file = f"{base}/file"
url_redirect = f"{base}/redirect"

res_all = run_attack_modules(base, modules=["recon", "idor", "fuzz", "rate"])
print(f"[OK] Módulos originais: {len(res_all['findings'])} achados")

# CORS
r = run_attack_modules(url_cors, modules=["cors"])
assert any(f["Categoria"] == "CORS" and f["Tipo"] == "Achado Ativo" and f["Prioridade"] == "Alta" for f in r["findings"]), r["findings"]
print("[OK] CORS: reflexo de origem + credenciais -> Achado Ativo Alta")

# HTTP Methods
r = run_attack_modules(url_method, modules=["methods"])
assert any("TRACE" in f["Item"] and f["Tipo"] == "Achado Ativo" for f in r["findings"]), r["findings"]
print("[OK] HTTP Methods: TRACE habilitado -> Achado Ativo")

# Path Traversal
r = run_attack_modules(url_file, modules=["traversal"], traversal_param="file")
assert any(f["Categoria"] == "Path Traversal" and f["Tipo"] == "Achado Ativo" and f["Prioridade"] == "Alta" for f in r["findings"]), r["findings"]
print("[OK] Path Traversal: /etc/passwd lido -> Achado Ativo Alta")

# Open Redirect
r = run_attack_modules(url_redirect, modules=["redirect"])
assert any(f["Categoria"] == "Open Redirect" and f["Tipo"] == "Achado Ativo" for f in r["findings"]), r["findings"]
print("[OK] Open Redirect: Location externo -> Achado Ativo")

# SQLi (error-based)
r = run_attack_modules(f"{base}/sqli", modules=["sqli"], web_param="id")
assert any(f["Categoria"] == "SQL Injection" and f["Tipo"] == "Achado Ativo" for f in r["findings"]), r["findings"]
print("[OK] SQLi: erro de banco detectado -> Achado Ativo")

# XSS (reflexo sem encoding)
r = run_attack_modules(f"{base}/xss", modules=["xss"], web_param="q")
assert any(f["Categoria"] == "XSS" and f["Tipo"] == "Achado Ativo" for f in r["findings"]), r["findings"]
print("[OK] XSS: marcador refletido sem encoding -> Achado Ativo")

# Credenciais (lab): admin/admin funciona
r = run_attack_modules(f"{base}/login", modules=["creds"])
assert any(f["Categoria"] == "Credenciais" and f["Tipo"] == "Achado Ativo" for f in r["findings"]), r["findings"]
print("[OK] Credenciais: admin/admin validada no lab -> Achado Ativo")

# Verifica labels
assert len(MODULE_LABELS) == 11
print("[OK] 11 módulos registrados no engine")

server.shutdown()
print("VALIDAÇÃO COMPLETA")
