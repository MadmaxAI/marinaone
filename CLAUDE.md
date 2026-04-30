# Marina One — Guia para o Claude Code

## Regra principal — NUNCA publicar em produção sem aprovação

Após qualquer alteração de código, o Claude deve:
1. Aplicar as mudanças nos arquivos
2. Rodar `testar.bat` para atualizar o ambiente local
3. Informar ao usuário: **"Alteração feita. Teste em http://localhost:3000 e me diga 'aprovado' para publicar."**
4. **AGUARDAR** o usuário dizer "aprovado" (ou variações: "ok", "pode publicar", "publish", "deploy")
5. Somente então rodar `publicar.bat "descrição"`

## NUNCA fazer isso sozinho
- Nunca rodar `publicar.bat` sem aprovação explícita do usuário
- Nunca fazer `git push` diretamente
- Nunca fazer `railway up` sem aprovação

## Fluxo obrigatório

```
Claude altera código
        ↓
Claude roda: testar.bat
        ↓
Claude diz: "Teste em localhost:3000 (vX.Y.Z) e diga 'aprovado'"
        ↓         ↑ SEMPRE informar a versão atual do package.json
Usuário testa e diz: "aprovado"
        ↓
Claude roda: publicar.bat "descrição da alteração"
        ↓
Deploy automático no Railway ✅
```

## Regra de comunicação — versão obrigatória

Ao finalizar qualquer alteração e avisar o usuário para testar, SEMPRE informar:
- A versão atual (ex: "v2.0.8") que está rodando no ambiente local
- Exemplo: **"Alteração feita. Teste em http://localhost:3000 (v2.0.8) e me diga 'aprovado' para publicar."**

## Comandos disponíveis

| Comando | Quando usar |
|---------|------------|
| `testar.bat` | Após cada alteração — aplica no Docker local |
| `publicar.bat "msg"` | Somente após aprovação do usuário |
| `publicar.bat "msg" minor` | Nova funcionalidade aprovada |
| `publicar.bat "msg" major` | Mudança grande aprovada |

## Ambientes

| Ambiente | URL | Banco |
|----------|-----|-------|
| Local (Docker) | http://localhost:3000 | PostgreSQL local (marinaone_db) |
| Produção (Railway) | https://marina-one-app.up.railway.app | PostgreSQL Railway |

## Tenant local
O ambiente local usa `SINGLE_TENANT_SLUG=demo` — acesse direto sem `?tenant=`.

## Stack
- Node.js 20 + PostgreSQL (postgres.js)
- Docker Compose para dev local
- Railway + GitHub Actions para produção
- Dockerfile como base de build
