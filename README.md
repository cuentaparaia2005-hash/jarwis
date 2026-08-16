# JARWIS

Agente ReAct autónomo de **auditoría de seguridad** que se ejecuta **dentro de Kali Linux**.
Tú le das un objetivo, un LLM local (**LM Studio**) razona y propone los comandos, JARWIS los
ejecuta en la propia Kali, y el resultado vuelve al LLM para decidir el siguiente paso — en bucle
hasta cumplir el objetivo. Genera un **informe HTML** al terminar.

- **Ejecución local** en Kali (subprocess, sin SSH).
- **Sin dependencias de Python** (solo la stdlib) → no necesita `pip` ni entornos virtuales.
- **Auto-instala** por `apt` las herramientas de auditoría que falten (nmap, nikto, gobuster,
  hydra, metasploit, aircrack-ng, wifite, reaver, hcxtools, …).
- Protocolo JSON, detección de repeticiones/estancamiento, confirmación de comandos peligrosos,
  auditoría WiFi y resumen final.

> ⚠️ Úsalo **solo contra sistemas y redes de tu propiedad o con autorización explícita**.

## Requisitos

- Kali Linux (o derivada Debian) con **Python 3** (ya viene de serie).
- **LM Studio** accesible por red con un modelo de chat cargado y *Serve on Local Network* activo.

## Instalación en otra Kali

**Opción A — descarga directa (un comando):**

```bash
sudo curl -fsSL https://raw.githubusercontent.com/USUARIO/REPO/main/jarwis.py -o /usr/local/bin/jarwis && sudo chmod +x /usr/local/bin/jarwis
```

**Opción B — clonando el repo:**

```bash
git clone https://github.com/USUARIO/REPO.git
cd REPO
bash install.sh
```

Ambas dejan el comando `jarwis` disponible en el sistema.

## Uso

```bash
jarwis
```

o con el objetivo directo:

```bash
jarwis "escanea 192.168.1.66 y dime servicios y versiones"
```

Al arrancar pregunta el **usuario**, la **IP de LM Studio** y deja **elegir el modelo** cargado;
la contraseña de sudo se pide en cada ejecución (no se guarda). Los informes se guardan en
`~/Desktop/Jarwis/` en formato HTML.

## Auditoría WiFi

Para monitor mode / captura de handshakes necesitas un adaptador WiFi con soporte de *monitor
mode* (en una VM, pásalo por USB passthrough). El preflight detecta las interfaces y te avisa si
solo hay una (ponerla en monitor cortaría tu conectividad/LLM).

## Configuración

Los valores por defecto (IP de LM Studio, tiempos, nº de iteraciones, lista de herramientas, etc.)
están en el bloque `CONFIG` al principio de `jarwis.py`.
