#!/bin/bash
# ============================================================
#  Marina One — Script de Atualização (Linux / VPS)
#  Uso: bash update.sh
#  Executar como o usuário que roda a aplicação (não root)
# ============================================================
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="marina-one"
BACKUP_DIR="$APP_DIR/../marina-backups"
DB_FILE="$APP_DIR/marina.db"
DATE=$(date +%Y-%m-%d_%H-%M-%S)

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Marina One — Atualização do Sistema    ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "📂 Diretório: $APP_DIR"
echo "📅 Data/Hora: $DATE"
echo ""

cd "$APP_DIR"

# ── 1. Verificar dependências ─────────────────────────────
echo "▶ Verificando dependências..."
command -v node  >/dev/null || { echo "❌ node não encontrado"; exit 1; }
command -v git   >/dev/null || { echo "❌ git não encontrado"; exit 1; }
command -v pm2   >/dev/null || { echo "❌ pm2 não encontrado — instale: npm i -g pm2"; exit 1; }
NODE_VER=$(node -e "console.log(process.versions.node.split('.')[0])")
[ "$NODE_VER" -ge 20 ] || { echo "❌ Node.js 20+ necessário (atual: v$NODE_VER)"; exit 1; }
echo "   Node.js v$(node -v | tr -d v)  ✓"

# ── 2. Backup do banco ANTES de qualquer mudança ──────────
echo ""
echo "▶ Criando backup do banco de dados..."
mkdir -p "$BACKUP_DIR"
cp "$DB_FILE" "$BACKUP_DIR/marina-pre-update-$DATE.db"
# Mantém apenas os últimos 30 backups
ls -t "$BACKUP_DIR"/marina-pre-update-*.db 2>/dev/null | tail -n +31 | xargs rm -f 2>/dev/null || true
echo "   Salvo em: $BACKUP_DIR/marina-pre-update-$DATE.db  ✓"

# ── 3. Versão atual ───────────────────────────────────────
OLD_VERSION=$(node -e "console.log(require('./package.json').version)" 2>/dev/null || echo "?")
OLD_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "?")
echo ""
echo "▶ Versão atual: v$OLD_VERSION ($OLD_HASH)"

# ── 4. Buscar atualizações do repositório ─────────────────
echo ""
echo "▶ Buscando atualizações (git pull)..."
git fetch origin main 2>&1
REMOTE_HASH=$(git rev-parse origin/main)
LOCAL_HASH=$(git rev-parse HEAD)

if [ "$REMOTE_HASH" = "$LOCAL_HASH" ]; then
  echo "   Já está na versão mais recente. Nenhuma atualização disponível."
  read -p "   Forçar reinicialização mesmo assim? [s/N] " FORCE
  [[ "$FORCE" =~ ^[sS]$ ]] || { echo "Cancelado."; exit 0; }
else
  COMMITS=$(git log HEAD..origin/main --oneline 2>/dev/null)
  echo ""
  echo "   Atualizações disponíveis:"
  echo "$COMMITS" | sed 's/^/   • /'
  echo ""
  git pull origin main
fi

# ── 5. Nova versão ────────────────────────────────────────
NEW_VERSION=$(node -e "console.log(require('./package.json').version)" 2>/dev/null || echo "?")
NEW_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "?")
echo ""
echo "▶ Nova versão: v$NEW_VERSION ($NEW_HASH)"

# ── 6. Validação mínima dos arquivos críticos ─────────────
echo ""
echo "▶ Validando arquivos..."
[ -f "$APP_DIR/server.js" ]    || { echo "❌ server.js não encontrado!"; exit 1; }
[ -f "$APP_DIR/frontend.html" ] || { echo "❌ frontend.html não encontrado!"; exit 1; }
node --check "$APP_DIR/server.js" 2>&1 && echo "   server.js — sintaxe OK  ✓" || {
  echo "❌ Erro de sintaxe em server.js! Revertendo..."
  git checkout HEAD~1 -- server.js
  exit 1
}

# ── 7. Reiniciar aplicação ────────────────────────────────
echo ""
echo "▶ Reiniciando via PM2..."
if pm2 describe "$APP_NAME" > /dev/null 2>&1; then
  pm2 restart "$APP_NAME" --update-env
else
  pm2 start server.js --name "$APP_NAME"
fi
sleep 3

# ── 8. Health check ───────────────────────────────────────
echo ""
echo "▶ Verificando saúde da aplicação..."
PORT=$(node -e "console.log(process.env.PORT||3000)")
MAX=10; COUNT=0
until curl -sf "http://localhost:$PORT/api/version" > /tmp/mo_version.json 2>/dev/null; do
  COUNT=$((COUNT+1))
  [ $COUNT -ge $MAX ] && { echo "❌ Health check falhou após ${MAX}s. Verifique: pm2 logs $APP_NAME"; exit 1; }
  echo "   Aguardando... ($COUNT/$MAX)"
  sleep 1
done

RUNNING_VER=$(node -e "const d=require('/tmp/mo_version.json');console.log(d.version+' ('+d.git_hash+')')" 2>/dev/null || echo "?")
echo "   Aplicação respondendo: v$RUNNING_VER  ✓"

# ── 9. Resumo ─────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║            Atualização Concluída!        ║"
echo "╠══════════════════════════════════════════╣"
printf "║  %-40s║\n" "Versão anterior : v$OLD_VERSION ($OLD_HASH)"
printf "║  %-40s║\n" "Versão atual    : v$NEW_VERSION ($NEW_HASH)"
printf "║  %-40s║\n" "Banco backup    : marina-pre-update-$DATE"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "✅ Sistema atualizado com sucesso!"
echo ""
