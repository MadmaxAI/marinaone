#!/bin/bash
# ============================================================
#  Marina One — Script de Publicação
#  Uso: bash publicar.sh "descrição da alteração" [patch|minor|major]
#  Ex:  bash publicar.sh "corrige cálculo de contratos" patch
#       bash publicar.sh "novo módulo de reservas" minor
# ============================================================

set -e

MENSAGEM="${1:-"atualização do sistema"}"
TIPO="${2:-patch}"   # patch | minor | major

# ── Cores ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; RESET='\033[0m'

echo -e "${CYAN}🚢  Marina One — Publicação${RESET}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

# ── 1. Verificar se há alterações ─────────────────────────
if git diff --quiet && git diff --staged --quiet; then
  echo -e "${YELLOW}⚠  Nenhuma alteração detectada.${RESET}"
  echo -e "   Adicione suas mudanças com: ${CYAN}git add .${RESET}"
  exit 0
fi

# ── 2. Bump de versão ─────────────────────────────────────
VERSAO_ATUAL=$(node -p "require('./package.json').version")
echo -e "${BLUE}📦  Versão atual: ${YELLOW}$VERSAO_ATUAL${RESET}"

# Calcular nova versão
IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSAO_ATUAL"
case "$TIPO" in
  major) MAJOR=$((MAJOR+1)); MINOR=0; PATCH=0 ;;
  minor) MINOR=$((MINOR+1)); PATCH=0 ;;
  *)     PATCH=$((PATCH+1)) ;;
esac
NOVA_VERSAO="${MAJOR}.${MINOR}.${PATCH}"

echo -e "${GREEN}🆕  Nova versão:   ${YELLOW}$NOVA_VERSAO${RESET}"

# Atualizar package.json
node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  pkg.version = '$NOVA_VERSAO';
  fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
  console.log('package.json atualizado');
"

# ── 3. Registrar no CHANGELOG ─────────────────────────────
DATA=$(date '+%Y-%m-%d')
ENTRADA="## [$NOVA_VERSAO] — $DATA\n- $MENSAGEM\n"

if [ -f CHANGELOG.md ]; then
  # Inserir após a primeira linha (título)
  TITULO=$(head -1 CHANGELOG.md)
  RESTO=$(tail -n +2 CHANGELOG.md)
  echo -e "$TITULO\n\n$ENTRADA$RESTO" > CHANGELOG.md
else
  echo -e "# Changelog — Marina One\n\n$ENTRADA" > CHANGELOG.md
fi

echo -e "${GREEN}📝  CHANGELOG.md atualizado${RESET}"

# ── 4. Commit + Tag + Push ────────────────────────────────
git add -A
git commit -m "v$NOVA_VERSAO: $MENSAGEM"
git tag "v$NOVA_VERSAO" -m "v$NOVA_VERSAO: $MENSAGEM"
git push origin main
git push origin "v$NOVA_VERSAO"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}✅  Publicado! v$NOVA_VERSAO → GitHub → Railway${RESET}"
echo -e "${CYAN}🌐  https://marina-one-app-production.up.railway.app${RESET}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
