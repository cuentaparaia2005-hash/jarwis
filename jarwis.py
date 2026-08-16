#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JARWIS — agente ReAct autónomo que se ejecuta DENTRO de Kali Linux.

  · Los comandos se ejecutan en LOCAL (subprocess, shell bash).
  · El razonamiento lo hace un LLM REMOTO en LM Studio (Windows) por red.
  · Bucle: objetivo -> LLM propone comando -> se ejecuta en Kali -> el
    resultado vuelve al LLM -> nuevo comando... hasta cumplir el objetivo.

Solo usa la librería estándar de Python 3 (NO requiere pip).
Uso:   python3 jarwis.py   [ "objetivo opcional" ]
"""

import os
import re
import sys
import json
import html
import time
import shlex
import socket
import ipaddress
import getpass
import datetime
import subprocess
import urllib.request
import urllib.error

# ============================================================
#  CONFIG por defecto (editable). La conexión se pregunta al arrancar.
# ============================================================
DEFAULT_LM_IP    = "192.168.1.250"      # IP por defecto de LM Studio (se puede cambiar al arrancar)
LLM_PORT         = 1234
LLM_MODEL        = "qwen3.6-35b-a3b-uncensored-hauhaucs-aggressive"
LLM_API_KEY      = "lm-studio"          # LM Studio ignora la clave (auth desactivada)
LLM_TEMPERATURE  = 0.3
LLM_MAX_TOKENS   = 1536                 # ajustado a contexto de 8192
LLM_TIMEOUT      = 600
DISABLE_THINKING = True                 # añade /no_think (evita respuestas vacías en modelos Qwen)

CMD_TIMEOUT         = 300               # seg. máximos por comando
MAX_ITERATIONS      = 25
STAGNATION_LIMIT    = 6                 # iteraciones sin progreso antes de cortar
MAX_OUTPUT_CHARS    = 12000
HISTORY_CHAR_BUDGET = 18000

RESULTS_DIR   = os.path.expanduser("~/jarwin_resultados")
ALLOWED_SCOPE = "0.0.0.0/0"             # todos los destinos autorizados (sin restricción de ámbito)
DEBUG         = False

# Herramientas de auditoría (binario -> paquete apt). Se instalan si faltan.
AUDIT_TOOLS = {
    # --- red / descubrimiento / recon ---
    "nmap": "nmap", "masscan": "masscan", "netdiscover": "netdiscover",
    "arp-scan": "arp-scan", "nc": "netcat-traditional", "curl": "curl",
    "dnsenum": "dnsenum", "dnsrecon": "dnsrecon", "tshark": "tshark",
    # --- lectura / consulta web ---
    "w3m": "w3m", "lynx": "lynx", "jq": "jq", "whois": "whois",
    # --- web ---
    "whatweb": "whatweb", "nikto": "nikto", "gobuster": "gobuster",
    "dirb": "dirb", "wpscan": "wpscan", "sqlmap": "sqlmap",
    # --- credenciales / smb / explotación ---
    "hydra": "hydra", "enum4linux": "enum4linux", "smbclient": "smbclient",
    "msfconsole": "metasploit-framework",
    # --- WiFi ---
    "iw": "iw", "iwconfig": "wireless-tools",
    "aircrack-ng": "aircrack-ng", "airmon-ng": "aircrack-ng",
    "airodump-ng": "aircrack-ng", "aireplay-ng": "aircrack-ng",
    "reaver": "reaver", "bully": "bully", "wifite": "wifite",
    "hcxdumptool": "hcxdumptool", "hcxpcapngtool": "hcxtools", "mdk4": "mdk4",
}

# Comandos destructivos -> exigen confirmación
DANGEROUS_PATTERNS = [
    r"\brm\s+-[a-z]*r[a-z]*f", r"\brm\s+-[a-z]*f[a-z]*r", r"\brm\s+-rf\b",
    r"\bmkfs\b", r"\bdd\s+if=", r"\bshred\b", r"\bwipefs\b",
    r">\s*/dev/sd", r">\s*/dev/nvme",
    r":\(\)\s*\{.*\}\s*;\s*:",
    r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bpoweroff\b", r"\binit\s+0\b",
    r"\biptables\s+-F", r"\bufw\s+disable", r"\bufw\s+reset",
    r"\buserdel\b", r"\bgroupdel\b", r"\bpasswd\b", r"\bchpasswd\b",
    r"\bchmod\s+-R\s+0*00\b",
    r"\bcrontab\s+-r\b",
    r"\bcurl\b[^|]*\|\s*(sudo\s+)?(ba)?sh", r"\bwget\b[^|]*\|\s*(sudo\s+)?(ba)?sh",
]

# Ataques WiFi activos/disruptivos -> exigen confirmación (solo contra red propia)
WIRELESS_ATTACK_PATTERNS = [
    r"aireplay-ng[^|]*(--deauth|-0)\b", r"\bmdk4\b", r"\bmdk3\b",
    r"\bairbase-ng\b", r"\bwifijammer\b", r"bettercap[^|]*deauth",
    r"\bwifite\b",                      # wifite lanza ataques activos por defecto
]

# ============================================================
#  Colores ANSI
# ============================================================
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    CYAN = "\033[36m"; YELLOW = "\033[33m"; GREEN = "\033[32m"
    RED = "\033[31m"; GRAY = "\033[90m"; BLUE = "\033[34m"; MAG = "\033[35m"

def c(text, color):
    return f"{color}{text}{C.RESET}"

# ============================================================
#  Estado global de conexión (se rellena en el asistente)
# ============================================================
LLM_BASE = f"http://{DEFAULT_LM_IP}:{LLM_PORT}/v1"
SUDO_PASSWORD = ""

# ============================================================
#  Prompt de sistema
# ============================================================
def build_system_prompt():
    p = f"""Eres JARWIS, un asistente autónomo de auditoría de seguridad que se ejecuta DENTRO de una
máquina Kali Linux, en la RED/LABORATORIO PROPIO del operador. Tú NO ejecutas: propones comandos y
un orquestador LOCAL los ejecuta en la MISMA Kali (shell bash, no interactiva) y te devuelve la salida real.

Entorno:
- Audita únicamente objetivos AUTORIZADOS por el operador (su laboratorio, su red, máquinas de
  HackTheBox u otros entornos con permiso). El reconocimiento pasivo del entorno WiFi es aceptable,
  pero NUNCA lances ataques activos (deauth, jamming, rogue-AP) contra redes o clientes que no sean del operador.
- El usuario tiene sudo (contraseña disponible); usa 'sudo' cuando haga falta (nmap -sS, airmon-ng, etc.).
- Cada comando se ejecuta INDEPENDIENTE en bash no interactivo: el estado (cd, variables) NO persiste.
  Encadena pasos con && o usa rutas absolutas.
- El comando debe ir en UNA sola línea. NADA de heredocs (<<EOF), ni multilínea, ni programas interactivos.

Auditoría WiFi:
- Modo monitor: `sudo airmon-ng start <iface>` crea <iface>mon; `sudo airmon-ng stop <iface>mon` lo revierte.
- ¡IMPORTANTE! poner en modo monitor la interfaz que da conectividad CORTA esa conexión (y podrías perder
  el acceso al LLM). Usa una interfaz de auditoría DISTINTA de la que da Internet/acceso al LLM. Si solo
  hay una interfaz WiFi, adviértelo en 'thought' antes de tocarla.
- Flujo típico: `iw dev` para ver interfaces -> modo monitor -> `airodump-ng <ifacemon>` para listar
  APs/clientes -> centrarse en el BSSID/canal del operador -> capturar handshake WPA (o PMKID con
  hcxdumptool) -> crackear con aircrack-ng contra un diccionario (p.ej. /usr/share/wordlists/rockyou.txt).

Consulta web (tienes acceso a Internet a través de Kali):
- Puedes investigar en la web ejecutando comandos: `curl -s <url>` para descargar contenido, y
  `w3m -dump <url>` o `lynx -dump <url>` para leer HTML como texto legible. Usa `jq` para APIs JSON.
- Útil para: buscar CVEs de una versión detectada, credenciales por defecto de un dispositivo/modelo,
  documentación de un servicio, exploits públicos, etc.
- Búsqueda rápida:
  `curl -s "https://html.duckduckgo.com/html/?q=TU+BUSQUEDA" | w3m -dump -T text/html | head -50`.
- Añade siempre un límite (| head) para no traer páginas enormes.
- Esto es DISTINTO de escanear: consultar páginas web públicas para informarte está permitido; no lo
  confundas con escanear o atacar máquinas.

Tu tarea: dado el OBJETIVO, avanza paso a paso. En CADA turno responde UN único objeto JSON con este esquema:
{{
  "thought": "razonamiento breve sobre el estado y el siguiente paso",
  "action": "run_command"  o  "finish",
  "command": "el comando exacto para bash (cadena vacía si action es finish)",
  "goal_reached": true o false,
  "final_answer": "al terminar, resumen claro en español; si no, cadena vacía"
}}

Reglas:
- Responde SOLO con el objeto JSON. Sin ``` , sin texto extra, sin <think>.
- Un único comando por turno. Espera su resultado antes del siguiente.
- Analiza cada resultado: si hay un error (herramienta, sintaxis...), corrige y reintenta.
- NO repitas un comando ya ejecutado ni relances un escaneo lento (p.ej. `nmap -sV` completo) si ya tienes
  su resultado. Si un servicio ya salió como '?' o no responde tras 1-2 intentos, anótalo y cambia de técnica.
- Con Metasploit agrupa módulos en UNA invocación: `msfconsole -q -x "use ...; run; use ...; run; exit"`.
- Si tras varios intentos no avanzas, FINALIZA (action="finish", goal_reached=false) y resume en
  final_answer lo que SÍ hayas averiguado y qué queda pendiente.
- Escribe "thought" y "final_answer" SIEMPRE en español."""
    if DISABLE_THINKING:
        p += "\n/no_think"
    return p

RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "react_step", "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "thought": {"type": "string"},
                "action": {"type": "string", "enum": ["run_command", "finish"]},
                "command": {"type": "string"},
                "goal_reached": {"type": "boolean"},
                "final_answer": {"type": "string"},
            },
            "required": ["thought", "action", "command", "goal_reached", "final_answer"],
            "additionalProperties": False,
        },
    },
}

# ============================================================
#  Cliente LM Studio (solo urllib, sin dependencias)
# ============================================================
def _http_json(url, payload=None, timeout=30):
    headers = {"Authorization": f"Bearer {LLM_API_KEY}"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    else:
        req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

def _message_content(msg):
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content") or ""
    if isinstance(content, list):
        content = "".join(b.get("text", "") for b in content if isinstance(b, dict))
    if content and content.strip():
        return content
    for key in ("reasoning_content", "reasoning"):
        r = msg.get(key)
        if isinstance(r, str) and r.strip():
            return r
    return content or ""

def call_llm(messages, use_schema=True):
    payload = {
        "model": LLM_MODEL, "messages": messages,
        "temperature": LLM_TEMPERATURE, "max_tokens": LLM_MAX_TOKENS, "stream": False,
    }
    if use_schema:
        payload["response_format"] = RESPONSE_FORMAT
    data = _http_json(f"{LLM_BASE}/chat/completions", payload, timeout=LLM_TIMEOUT)
    return _message_content(data["choices"][0]["message"])

# ============================================================
#  Parseo de la respuesta del modelo
# ============================================================
def strip_think(text):
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

def extract_json(text):
    if not text:
        return None
    text = strip_think(text)
    text = re.sub(r"^```(?:json)?", "", text.strip())
    text = re.sub(r"```$", "", text.strip()).strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except Exception:
                        break
        start = text.find("{", start + 1)
    return None

def clean_command(cmd):
    cmd = (cmd or "").strip()
    cmd = re.sub(r"^```(?:bash|sh)?", "", cmd).strip()
    cmd = re.sub(r"```$", "", cmd).strip()
    return cmd

def clean_for_llm(text):
    """Quita los volcados de fingerprint de nmap (SF:/SF-Port) que inflan la salida."""
    keep = []
    for ln in (text or "").splitlines():
        s = ln.lstrip()
        if s.startswith("SF:") or s.startswith("SF-Port"):
            continue
        if "please submit the following fingerprint" in s:
            continue
        if "unrecognized despite returning data" in s:
            continue
        keep.append(ln)
    return "\n".join(keep)

def get_step(messages):
    raw = ""
    try:
        raw = call_llm(messages, use_schema=True)
    except urllib.error.HTTPError:
        raw = call_llm(messages, use_schema=False)
    if DEBUG:
        print(c(f"[DEBUG raw] {raw!r}", C.GRAY))
    data = extract_json(raw)
    if data is None:
        corrective = messages + [{"role": "user",
            "content": "Tu respuesta no era JSON válido o venía vacía. Responde SOLO con el objeto "
                       "JSON del esquema, sin texto ni <think>."}]
        raw = call_llm(corrective, use_schema=False)
        data = extract_json(raw)
    return data, raw

def _norm_cmd(cmd):
    return re.sub(r"\s+", " ", (cmd or "").strip()).lower()

# ============================================================
#  Chequeos de seguridad
# ============================================================
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _allowed_networks():
    """Redes autorizadas a partir de ALLOWED_SCOPE (CIDR, coma para varias) + loopback."""
    nets = []
    for part in ALLOWED_SCOPE.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass
    nets.append(ipaddress.ip_network("127.0.0.0/8"))
    return nets

def _out_of_scope(cmd):
    nets = _allowed_networks()
    bad = []
    for ip in _IP_RE.findall(cmd):
        if ip == "0.0.0.0":
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not any(addr in n for n in nets):
            bad.append(ip)
    return bad

def needs_confirmation(cmd):
    """Devuelve (bool, motivo) si el comando requiere confirmación del operador."""
    low = cmd.lower()
    if any(re.search(p, low) for p in DANGEROUS_PATTERNS):
        return True, "COMANDO POTENCIALMENTE DESTRUCTIVO"
    if any(re.search(p, low) for p in WIRELESS_ATTACK_PATTERNS):
        return True, "ATAQUE WiFi ACTIVO (deauth/jamming/rogue-AP) — solo contra tu propia red"
    oos = _out_of_scope(cmd)
    if oos:
        return True, f"OBJETIVO FUERA DE ÁMBITO ({', '.join(oos)}) — permitido: {ALLOWED_SCOPE}"
    return False, ""

def ask_confirm(cmd, reason):
    print(c(f"\n  /!\\  {reason}", C.RED + C.BOLD))
    print(c(f"      {cmd}", C.YELLOW))
    try:
        ans = input(c("  ¿Ejecutar este comando? [s/N] ", C.RED)).strip().lower()
    except EOFError:
        return False
    return ans in ("s", "si", "sí", "y", "yes")

# ============================================================
#  Ejecutor LOCAL (subprocess)
# ============================================================
def run_local(cmd, timeout=CMD_TIMEOUT):
    """Ejecuta un comando en la Kali local con bash; inyecta sudo si hace falta."""
    exec_cmd = cmd
    if re.match(r"^\s*sudo\s+", cmd):
        rest = re.sub(r"^\s*sudo\s+", "", cmd, count=1)
        exec_cmd = f"echo {shlex.quote(SUDO_PASSWORD)} | sudo -S -p '' {rest}"
    try:
        p = subprocess.run(["bash", "-c", exec_cmd], capture_output=True,
                           text=True, errors="replace", timeout=timeout)
        return p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        partial = e.stdout if isinstance(e.stdout, str) else ""
        return partial, f"[TIMEOUT] el comando superó {timeout}s y se abortó.", -1
    except Exception as e:
        return "", f"[ERROR] {e}", -1

# ============================================================
#  Asistente de configuración (se pregunta en cada arranque)
# ============================================================
def _autodetect_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _results_dir_for(user):
    """Carpeta 'Jarwis' en el Escritorio del usuario indicado."""
    try:
        import pwd
        home = pwd.getpwnam(user).pw_dir
    except Exception:
        home = os.path.expanduser("~")
    for d in ("Desktop", "Escritorio"):
        if os.path.isdir(os.path.join(home, d)):
            return os.path.join(home, d, "Jarwis")
    return os.path.join(home, "Desktop", "Jarwis")

def _chown_to_user(path, user):
    """Si corremos como root, cede la propiedad al usuario (para abrir el HTML sin ser root)."""
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return
    try:
        import pwd
        pw = pwd.getpwnam(user)
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except Exception:
        pass

def choose_model():
    """Lista los modelos cargados en LM Studio y deja elegir el de chat."""
    global LLM_MODEL
    root = re.sub(r"/v1/?$", "", LLM_BASE)
    types = {}
    try:  # API nativa de LM Studio: nos dice el 'type' (llm / embeddings)
        d = _http_json(f"{root}/api/v0/models", timeout=8)
        for m in d.get("data", []):
            types[m.get("id", "")] = m.get("type", "")
    except Exception:
        pass
    try:
        d = _http_json(f"{LLM_BASE}/models", timeout=8)
        ids = [m.get("id", "") for m in d.get("data", []) if m.get("id")]
    except Exception as e:
        print(c(f"  No pude listar modelos de LM Studio ({e}). Uso por defecto: {LLM_MODEL}", C.YELLOW))
        return LLM_MODEL
    # descarta modelos de embeddings (no sirven para chat)
    chat = [i for i in ids if types.get(i, "llm") != "embeddings" and "embed" not in i.lower()]
    chat = chat or ids
    if not chat:
        print(c(f"  LM Studio no reporta modelos. Uso por defecto: {LLM_MODEL}", C.YELLOW))
        return LLM_MODEL
    default_idx = chat.index(LLM_MODEL) + 1 if LLM_MODEL in chat else 1
    print(c("\n  Modelos disponibles en LM Studio:", C.BOLD))
    for n, mid in enumerate(chat, 1):
        mark = c("  (actual)", C.DIM) if mid == LLM_MODEL else ""
        print(f"    {c(str(n)+')', C.CYAN)} {mid}{mark}")
    while True:
        sel = input(f"  Elige modelo [{default_idx}]: ").strip()
        if not sel:
            idx = default_idx
            break
        if sel.isdigit() and 1 <= int(sel) <= len(chat):
            idx = int(sel)
            break
        print(c("    Opción no válida, escribe un número de la lista.", C.RED))
    LLM_MODEL = chat[idx - 1]
    print(c(f"  Modelo seleccionado: {LLM_MODEL}", C.GREEN))
    return LLM_MODEL

def setup_wizard():
    global LLM_BASE, SUDO_PASSWORD, RESULTS_DIR
    try:
        import readline  # edición de línea: flechas, borrado, historial en los input()
    except Exception:
        pass
    print(c("\n== Configuración (se pregunta en cada arranque; nada se guarda en disco) ==", C.BOLD))
    # La IP de Kali es la de esta misma máquina: se autodetecta, no se pregunta.
    kali_ip = _autodetect_ip()
    user_def = getpass.getuser()
    user = input(f"  Usuario                [{user_def}]: ").strip() or user_def
    lm_ip = input(f"  IP de LM Studio        [{DEFAULT_LM_IP}]: ").strip() or DEFAULT_LM_IP
    LLM_BASE = f"http://{lm_ip}:{LLM_PORT}/v1"
    choose_model()   # lista los modelos de LM Studio y deja elegir
    # Contraseña VISIBLE (a petición del operador). Enter si eres root (no se usa).
    pw = input("  Contraseña de sudo (visible; Enter si eres root): ")
    SUDO_PASSWORD = pw
    RESULTS_DIR = _results_dir_for(user)   # -> ~/Desktop/Jarwis del usuario
    print(c(f"  (Kali detectada en {kali_ip} · informes en {RESULTS_DIR})", C.DIM))
    return {"kali_ip": kali_ip, "user": user, "lm_ip": lm_ip}

# ============================================================
#  Preflight (Linux) con auto-instalación
# ============================================================
def _leader(label, width=36):
    lab = label + " "
    return lab + "." * max(3, width - len(lab))

def _pf_section(title):
    bar = "─" * max(3, 48 - len(title))
    print(c(f"\n  ┌─ {title} {bar}", C.BLUE + C.BOLD))

def _pf_row(label, status, detail=""):
    marks = {"ok": (C.GREEN, "✓"), "warn": (C.YELLOW, "!"),
             "fail": (C.RED, "✗"), "info": (C.CYAN, "·")}
    col, ic = marks.get(status, (C.GRAY, "?"))
    line = f"  {col}{ic}{C.RESET} {C.DIM}{_leader(label)}{C.RESET} "
    if detail:
        line += str(detail)
    print(line)

def autoinstall(pkgs):
    pkgs = sorted(set(pkgs))
    print(c(f"\n  Instalando paquetes que faltan: {' '.join(pkgs)}", C.YELLOW))
    print(c("  (esto puede tardar; metasploit-framework es grande)", C.DIM))
    run_local("sudo apt-get update", timeout=600)
    out, err, code = run_local(
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y " + " ".join(pkgs),
        timeout=2400)
    return code, out, err

def preflight(cfg):
    stats = {"ok": 0, "warn": 0, "fail": 0}
    def row(label, status, detail=""):
        if status in stats:
            stats[status] += 1
        _pf_row(label, status, detail)

    title = "COMPROBACIONES DEL ENTORNO (JARWIS)"
    w = 56
    print(c("\n  ╔" + "═" * w + "╗", C.CYAN + C.BOLD))
    print(c("  ║" + title.center(w) + "║", C.CYAN + C.BOLD))
    print(c("  ╚" + "═" * w + "╝", C.CYAN + C.BOLD))
    t0 = time.time()
    critical_ok = True

    # ── Sistema ───────────────────────────────────────────
    _pf_section("Sistema")
    row("Python", "info", sys.version.split()[0])
    out, _, _ = run_local("grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"'; uname -r")
    parts = [l.strip() for l in out.splitlines() if l.strip()]
    row("SO / kernel", "info", " · ".join(parts) if parts else "?")
    out, err, code = run_local("sudo id -u")
    last = out.strip().splitlines()[-1].strip() if out.strip() else ""
    if last == "0":
        row("sudo", "ok", "root disponible")
    else:
        row("sudo", "fail", f"la contraseña de sudo no funciona ({err.strip()[:40]})")
        critical_ok = False

    # ── LM Studio ─────────────────────────────────────────
    _pf_section(f"LM Studio ({LLM_BASE})")
    try:
        data = _http_json(f"{LLM_BASE}/models", timeout=10)
        ids = [m.get("id", "") for m in data.get("data", [])]
        row("API /v1/models", "ok", f"{len(ids)} modelo(s)")
        row("Modelo configurado", "ok" if LLM_MODEL in ids else "warn",
            LLM_MODEL if LLM_MODEL in ids else f"'{LLM_MODEL}' no aparece")
        try:
            t = time.time()
            test = call_llm([{"role": "system", "content": "Responde solo JSON."},
                             {"role": "user", "content": 'Devuelve {"ok": true}'}], use_schema=False)
            dt = (time.time() - t) * 1000
            if test and test.strip():
                row("Generación de texto", "ok", f"no vacío · {dt:.0f} ms")
            else:
                row("Generación de texto", "fail", "CONTENIDO VACÍO (sube LLM_MAX_TOKENS)")
                critical_ok = False
        except Exception as e:
            row("Generación de texto", "fail", e)
            critical_ok = False
    except Exception as e:
        row("API /v1/models", "fail", e)
        critical_ok = False

    # ── Herramientas (auto-instala las que falten) ────────
    _pf_section("Herramientas de auditoría")
    missing_bins, missing_pkgs = [], []
    for binname, pkg in AUDIT_TOOLS.items():
        if not _which(binname):
            missing_bins.append(binname)
            missing_pkgs.append(pkg)
    present_n = len(AUDIT_TOOLS) - len(missing_bins)
    row("Presentes", "ok", f"{present_n}/{len(AUDIT_TOOLS)}")
    if missing_bins:
        row("Ausentes", "warn", ", ".join(sorted(set(missing_bins))))
        code, out, err = autoinstall(missing_pkgs)
        still = [b for b, p in AUDIT_TOOLS.items() if b in missing_bins and not _which(b)]
        if not still:
            row("Auto-instalación", "ok", "todo instalado correctamente")
        else:
            row("Auto-instalación", "warn", f"siguen faltando: {', '.join(sorted(set(still)))}")
    else:
        row("Auto-instalación", "ok", "nada que instalar")

    # ── Red ───────────────────────────────────────────────
    _pf_section("Red")
    out, _, _ = run_local("ip -4 -br addr show | grep -v '127.0.0.1'")
    for ln in [l for l in out.splitlines() if l.strip()]:
        row("iface", "info", " ".join(ln.split()))
    out, _, _ = run_local("ip route get 1.1.1.1 2>/dev/null | head -1")
    m = re.search(r"dev\s+(\S+)", out)
    row("Salida a Internet", "ok" if m else "warn", f"vía {m.group(1)}" if m else "sin ruta por defecto")
    lm_host = re.sub(r"^https?://", "", LLM_BASE).split(":")[0]
    try:
        t = time.time()
        with socket.create_connection((lm_host, LLM_PORT), timeout=5):
            row(f"TCP LM Studio {lm_host}:{LLM_PORT}", "ok", f"{(time.time()-t)*1000:.0f} ms")
    except Exception as e:
        row(f"TCP LM Studio {lm_host}:{LLM_PORT}", "fail", e)
        critical_ok = False

    # ── WiFi ──────────────────────────────────────────────
    _pf_section("WiFi")
    out, _, _ = run_local("iw dev 2>/dev/null | awk '/Interface/{print $2}'")
    wifis = [l.strip() for l in out.splitlines() if l.strip()]
    if wifis:
        row("Interfaces WiFi", "ok", ", ".join(wifis))
        mon, _, _ = run_local("iw list 2>/dev/null | grep -A8 'Supported interface modes' | grep -ci monitor")
        can_mon = mon.strip().isdigit() and int(mon.strip()) > 0
        row("Modo monitor", "ok" if can_mon else "warn",
            "soportado" if can_mon else "no detectado (¿adaptador compatible?)")
        if len(wifis) < 2:
            row("Aviso", "warn", "1 sola WiFi: ponerla en monitor cortará tu Internet/LLM")
    else:
        row("Interfaces WiFi", "warn", "ninguna detectada (auditoría WiFi no disponible)")

    # ── Resultados ────────────────────────────────────────
    _pf_section("Resultados")
    try:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        testf = os.path.join(RESULTS_DIR, ".write_test")
        with open(testf, "w") as f:
            f.write("ok")
        os.remove(testf)
        row("Carpeta escribible", "ok", RESULTS_DIR)
    except Exception as e:
        row("Carpeta escribible", "fail", e)
        critical_ok = False

    dt = time.time() - t0
    ok_all = critical_ok and stats["fail"] == 0
    color = C.GREEN if ok_all else C.RED
    print(c(f"\n  └─ {stats['ok']} OK · {stats['warn']} avisos · {stats['fail']} fallos   ({dt:.1f}s)",
            color + C.BOLD))
    if not ok_all:
        print(c("     ⚠ Hay fallos críticos: corrige lo de arriba antes de continuar.", C.RED))
    return critical_ok

def _which(binname):
    from shutil import which
    return which(binname) is not None

# ============================================================
#  Resumen forzado
# ============================================================
def request_summary(messages):
    msgs = messages + [{"role": "user",
        "content": "Se detuvo el agente sin un 'finish' formal. Resume en español los HALLAZGOS "
                   "obtenidos (servicios, versiones, credenciales, redes WiFi, etc.) y qué queda "
                   "pendiente. Texto claro, SIN JSON ni <think>."}]
    try:
        return strip_think(call_llm(msgs, use_schema=False)).strip()
    except Exception as e:
        return f"(no se pudo generar el resumen automático: {e})"

def trim_history(messages):
    def total():
        return sum(len(m.get("content", "")) for m in messages)
    while total() > HISTORY_CHAR_BUDGET and len(messages) > 4:
        del messages[2:4]

# ============================================================
#  Informe HTML
# ============================================================
def save_report_html(objective, iterations, goal_reached, final_answer, elapsed, stopped_reason, cfg):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = datetime.datetime.now()
    path = os.path.join(RESULTS_DIR, ts.strftime("sesion_%Y%m%d_%H%M%S.html"))
    e = html.escape
    badge = ('<span class="ok">✅ Sí</span>' if goal_reached
             else '<span class="no">❌ No</span>')

    rows = ""
    for i, it in enumerate(iterations, 1):
        rows += f'<section class="iter"><h2>Iteración {i}</h2>'
        rows += f'<p class="thought"><b>Razonamiento:</b> {e(it.get("thought",""))}</p>'
        if it.get("command"):
            rows += f'<pre class="cmd">{e(it["command"])}</pre>'
            rows += f'<p class="meta">Código de salida: <code>{e(str(it.get("exit_code")))}</code></p>'
            body = (it.get("output") or "").strip() or "(sin salida)"
            rows += f'<details open><summary>Resultado</summary><pre class="out">{e(body)}</pre></details>'
        if it.get("note"):
            rows += f'<p class="note">ℹ {e(it["note"])}</p>'
        rows += "</section>"

    fa = e(final_answer).replace("\n", "<br>") if final_answer else "<i>(sin resumen)</i>"
    stop = f'<li><b>Motivo de parada:</b> {e(stopped_reason)}</li>' if stopped_reason else ""

    doc = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JARWIS — {e(ts.strftime('%Y-%m-%d %H:%M'))}</title>
<style>
  :root{{color-scheme:dark}}
  body{{background:#0f1419;color:#d7dde3;font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif;margin:0;padding:2rem}}
  .wrap{{max-width:1000px;margin:0 auto}}
  h1{{color:#7ee787;margin:0 0 .3rem}}
  .head ul{{list-style:none;padding:0;margin:.5rem 0 1.5rem;color:#9aa5b1}}
  .head li{{margin:.15rem 0}}
  .ok{{color:#7ee787;font-weight:600}} .no{{color:#ff7b72;font-weight:600}}
  h2{{color:#79c0ff;border-bottom:1px solid #21262d;padding-bottom:.3rem;margin-top:2rem}}
  .thought{{color:#c9d1d9}}
  pre{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:.8rem 1rem;overflow:auto;white-space:pre-wrap;word-break:break-word}}
  pre.cmd{{border-left:3px solid #d29922;color:#ffdf5d}}
  pre.out{{color:#adbac7;max-height:520px}}
  .meta,.note{{color:#768390;font-size:.9em}} .note{{color:#d29922}}
  code{{background:#161b22;padding:.1rem .35rem;border-radius:4px}}
  summary{{cursor:pointer;color:#768390;margin:.4rem 0}}
  .final{{background:#12261a;border:1px solid #238636;border-radius:10px;padding:1rem 1.3rem;margin-top:2rem}}
  .final h2{{color:#7ee787;border:0;margin:0 0 .5rem}}
</style></head><body><div class="wrap">
<div class="head">
  <h1>🤖 JARWIS — Informe de auditoría</h1>
  <ul>
    <li><b>Objetivo:</b> {e(objective)}</li>
    <li><b>Modelo:</b> <code>{e(LLM_MODEL)}</code></li>
    <li><b>Host:</b> {e(cfg.get('user',''))}@{e(cfg.get('kali_ip',''))} (Kali, ejecución local)</li>
    <li><b>Fecha:</b> {e(ts.strftime('%Y-%m-%d %H:%M:%S'))} · <b>Duración:</b> {elapsed:.1f} s · <b>Iteraciones:</b> {len(iterations)}</li>
    <li><b>Objetivo cumplido:</b> {badge}</li>
    {stop}
  </ul>
</div>
{rows}
<div class="final"><h2>🏁 Resultado final</h2><p>{fa}</p></div>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    # Si corremos como root, cede la propiedad de la carpeta y el HTML al usuario
    _chown_to_user(RESULTS_DIR, cfg.get("user", ""))
    _chown_to_user(path, cfg.get("user", ""))
    return path

# ============================================================
#  Bucle principal ReAct
# ============================================================
BANNER = r"""
   _   _   ___  _____      _____ ___
  | | / \ | _ \|_ _\ \    / /_ _/ __|   agente de auditoria en Kali
  | || A ||   / | | \ \/\/ / | |\__ \   (local + LLM remoto)
  |_||_|_||_|_\|___| \_/\_/ |___|___/
"""

def run_agent(objective, cfg):
    if not preflight(cfg):
        print(c("\nCorrige los fallos y vuelve a lanzar JARWIS.", C.RED))
        return

    print(c(f"\n== OBJETIVO ==\n{objective}\n", C.BOLD + C.MAG))
    messages = [
        {"role": "system", "content": build_system_prompt()},
        {"role": "user", "content": f"OBJETIVO: {objective}"},
    ]
    iterations = []
    goal_reached = False
    final_answer = ""
    seen_commands = set()
    stagnation = 0
    stopped_reason = ""
    t0 = time.time()

    try:
        for step in range(1, MAX_ITERATIONS + 1):
            trim_history(messages)
            print(c(f"\n──────── Iteración {step}/{MAX_ITERATIONS} ────────", C.BLUE + C.BOLD))

            data, raw = get_step(messages)
            if data is None:
                print(c("  [!] No obtuve JSON válido del modelo:", C.RED))
                print(c(f"      {raw!r}", C.GRAY))
                iterations.append({"thought": "(respuesta no parseable)", "command": "",
                                   "output": raw, "exit_code": None,
                                   "note": "El modelo no devolvió JSON válido; se aborta."})
                stopped_reason = "respuesta del modelo no parseable"
                break

            thought = str(data.get("thought", "")).strip()
            action = str(data.get("action", "run_command")).strip()
            command = clean_command(data.get("command", ""))
            gr = bool(data.get("goal_reached"))
            fa = str(data.get("final_answer", "")).strip()

            if thought:
                print(c("  Pensamiento: ", C.CYAN) + thought)

            if action == "finish" or gr or (not command):
                goal_reached = gr or (action == "finish")
                final_answer = fa or thought
                print(c("\n  ✔ El modelo declara el objetivo CUMPLIDO." if goal_reached
                        else "\n  ⏹ El modelo finaliza sin comando.", C.GREEN + C.BOLD))
                if final_answer:
                    print(c("\n== RESUMEN ==\n", C.BOLD) + final_answer)
                iterations.append({"thought": thought, "command": "", "output": "",
                                   "exit_code": None, "note": "Fin del ciclo."})
                break

            print(c("  Comando:     ", C.YELLOW) + command)

            need, reason = needs_confirmation(command)
            if need and not ask_confirm(command, reason):
                print(c("  ↩ Comando rechazado por el operador.", C.YELLOW))
                messages.append({"role": "assistant", "content": json.dumps(data, ensure_ascii=False)})
                messages.append({"role": "user",
                                 "content": "El operador RECHAZÓ ese comando. Propón una alternativa "
                                            "más segura o finaliza."})
                iterations.append({"thought": thought, "command": command, "output": "",
                                   "exit_code": None, "note": "Rechazado por el operador."})
                continue

            norm = _norm_cmd(command)
            is_repeat = norm in seen_commands
            seen_commands.add(norm)
            if is_repeat:
                print(c("  ↺ Comando repetido (ya ejecutado antes).", C.YELLOW))

            print(c("  Ejecutando en Kali (local)...", C.DIM))
            out, err, code = run_local(command)
            combined = out
            if err.strip():
                combined += ("\n[stderr]\n" + err if combined else "[stderr]\n" + err)

            shown = combined.strip() or "(sin salida)"
            print(c(f"  ── salida (exit={code}) ──", C.GRAY))
            print(shown)

            iterations.append({"thought": thought, "command": command,
                               "output": combined, "exit_code": code})

            unproductive = (is_repeat or code != 0 or "[TIMEOUT]" in err or not combined.strip())
            stagnation = stagnation + 1 if unproductive else 0

            for_llm = clean_for_llm(combined)
            if len(for_llm) > MAX_OUTPUT_CHARS:
                for_llm = (for_llm[:MAX_OUTPUT_CHARS] +
                           f"\n...[salida recortada; el comando SÍ terminó (exit={code}). NO lo reejecutes.]")
            if is_repeat:
                for_llm = ("AVISO: ya ejecutaste este comando; el resultado no cambia. "
                           "Cambia de enfoque o finaliza.\n\n" + for_llm)
            messages.append({"role": "assistant", "content": json.dumps(data, ensure_ascii=False)})
            messages.append({"role": "user",
                             "content": f"RESULTADO del comando (exit={code}), ya finalizó:\n{for_llm}"})

            if stagnation >= STAGNATION_LIMIT:
                stopped_reason = f"estancamiento ({stagnation} iteraciones sin progreso)"
                print(c(f"\n  ⏹ Corto el ciclo por {stopped_reason}.", C.YELLOW + C.BOLD))
                break
        else:
            stopped_reason = f"límite de {MAX_ITERATIONS} iteraciones"
            print(c(f"\n  ⏹ Límite de {MAX_ITERATIONS} iteraciones alcanzado.", C.YELLOW + C.BOLD))

    except KeyboardInterrupt:
        stopped_reason = "interrumpido por el usuario (Ctrl+C)"
        print(c("\n\n  Interrumpido (Ctrl+C). Guardando lo hecho...", C.YELLOW))

    elapsed = time.time() - t0
    if not final_answer:
        print(c("\n  Generando resumen de lo conseguido...", C.DIM))
        final_answer = request_summary(messages)
        if final_answer:
            print(c("\n== RESUMEN ==\n", C.BOLD) + final_answer)
    path = save_report_html(objective, iterations, goal_reached, final_answer,
                            elapsed, stopped_reason, cfg)
    print(c(f"\n📄 Informe HTML guardado en: {path}", C.GREEN + C.BOLD))
    print(c(f"   Ábrelo con doble clic en el Escritorio (carpeta Jarwis),", C.DIM))
    print(c(f"   o desde una terminal del usuario:  firefox '{path}'", C.DIM))

# ============================================================
#  main
# ============================================================
def main():
    if os.name != "nt":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    print(c(BANNER, C.MAG))
    if os.geteuid() == 0:
        print(c("  Aviso: estás como root; no hace falta. Ejecuta como tu usuario normal.", C.YELLOW))

    cfg = setup_wizard()

    if len(sys.argv) > 1:
        objective = " ".join(sys.argv[1:]).strip()
    else:
        try:
            objective = input(c("\nEscribe el OBJETIVO> ", C.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelado.")
            return
    if not objective:
        print("No hay objetivo. Saliendo.")
        return
    run_agent(objective, cfg)

if __name__ == "__main__":
    main()
