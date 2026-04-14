# ⚓ Marina One

Sistema completo de gestão de marina — backend Node.js + SQLite + frontend SPA single-file.

## 🚀 Deploy rápido

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/MadmaxAI/marinaone)

## 🌐 Acesso

| Campo | Valor |
|---|---|
| URL local | http://localhost:3000/frontend.html |
| Login | admin@marina.com |
| Senha | marina123 |

## ⚙️ Rodar localmente

Requer **Node.js 22+**

```bash
git clone https://github.com/MadmaxAI/marinaone.git
cd marinaone

# Windows
start.bat

# Ou direto:
node server.js
```

Acesse: http://localhost:3000/frontend.html

## 📦 Stack

- **Backend**: Node.js puro (`http`, `node:sqlite`, `crypto`) — sem dependências externas
- **Banco de dados**: SQLite nativo (Node 22+)
- **Frontend**: HTML/CSS/JS single-file com Chart.js (CDN)
- **Auth**: JWT (HMAC-SHA256)

## 🗂️ Módulos

| Módulo | Descrição |
|---|---|
| Dashboard | KPIs em tempo real, ocupação, receita |
| Fila | Operações de descida, subida e atracação |
| Clientes | Cadastro com tier VIP/Gold/Silver e LTV |
| Embarcações | Cadastro com histórico de operações |
| Vagas | 110 vagas (90 secas + 20 molhadas) com mapa visual |
| Contratos | Armazenagem seca e molhada com geração de cobranças |
| Financeiro | Cobranças, pagamentos, inadimplência |
| Loja / PDV | Carrinho, estoque, pedidos com QR Code PIX configurável |
| Manutenção | OS preventiva e corretiva com prioridades |
| Analytics | 40+ KPIs com gráficos Chart.js |
| Alertas | Alertas automáticos de estoque, inadimplência e OS |

## 🔧 Variáveis de ambiente (opcional)

```env
PORT=3000
JWT_SECRET=seu_secret_aqui
```

## 📁 Estrutura

```
marinaone/
├── server.js       # Backend completo (Node.js, sem dependências)
├── frontend.html   # SPA completa (single-file)
├── package.json    # Metadados e scripts
├── vercel.json     # Config de deploy Vercel
├── start.bat       # Atalho Windows
├── app.py          # Backend alternativo em Python/Flask
└── requirements.txt
```
