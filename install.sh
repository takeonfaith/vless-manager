#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo 'Запусти: sudo bash install.sh' >&2
  exit 1
fi
if [[ $(uname -s) != Linux ]]; then
  echo 'Установи менеджер на Linux VPS, а не на локальный Mac/Windows.' >&2
  exit 1
fi
if ! command -v python3 >/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3
fi
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 - "$SOURCE_DIR/vless-manager.py" <<'PY'
import pathlib,sys
compile(pathlib.Path(sys.argv[1]).read_text(), sys.argv[1], 'exec')
PY
install -m 0755 -o root -g root "$SOURCE_DIR/vless-manager.py" /usr/local/bin/vless-manager
echo 'Команда vless-manager установлена. Дальше: sudo vless-manager --help'
