#!/usr/bin/env bash
# Instalador de JARWIS: copia el agente a /usr/local/bin y lo deja como comando 'jarwis'.
set -e

SRC="$(cd "$(dirname "$0")" && pwd)/jarwis.py"

if [ ! -f "$SRC" ]; then
  echo "No encuentro jarwis.py junto a este script." >&2
  exit 1
fi

# quita posibles retornos de carro (\r) por si el archivo vino de Windows
sed -i 's/\r$//' "$SRC" 2>/dev/null || true

echo "Instalando 'jarwis' en /usr/local/bin (requiere sudo)..."
sudo install -m 755 "$SRC" /usr/local/bin/jarwis

echo
echo "  Listo. Ejecuta:   jarwis"
echo "  (la primera vez instalará las herramientas de auditoría que falten)"
