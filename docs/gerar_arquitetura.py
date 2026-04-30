
# -*- coding: utf-8 -*-
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)

# ── CORES ────────────────────────────────────────────────────────────────────
AZUL       = colors.HexColor('#1e3a5f')
AZUL_LIGHT = colors.HexColor('#2563eb')
CINZA      = colors.HexColor('#475569')
CINZA_LIGHT= colors.HexColor('#f1f5f9')
CINZA_MED  = colors.HexColor('#e2e8f0')
BRANCO     = colors.white
VERDE      = colors.HexColor('#10b981')
LARANJA    = colors.HexColor('#f59e0b')
ROXO       = colors.HexColor('#6366f1')
VERDE_DARK = colors.HexColor('#065f46')

W, H = A4
OUT  = os.path.join(os.path.dirname(__file__), 'Arquitetura Marina One.pdf')

styles = getSampleStyleSheet()

def st(name, parent='Normal', **kw):
    return ParagraphStyle(name, parent=styles[parent], **kw)

S_TITULO   = st('sTitulo',   fontSize=32, textColor=BRANCO,     alignment=TA_CENTER, leading=40, spaceAfter=8)
S_SUB      = st('sSub',      fontSize=14, textColor=colors.HexColor('#93c5fd'), alignment=TA_CENTER, leading=20, spaceAfter=6)
S_VERSION  = st('sVersion',  fontSize=11, textColor=colors.HexColor('#cbd5e1'), alignment=TA_CENTER, leading=16)
S_H1       = st('sH1',       fontSize=16, textColor=AZUL,        spaceBefore=18, spaceAfter=8,  fontName='Helvetica-Bold', leading=22)
S_H2       = st('sH2',       fontSize=12, textColor=AZUL_LIGHT,  spaceBefore=12, spaceAfter=6,  fontName='Helvetica-Bold', leading=16)
S_BODY     = st('sBody',     fontSize=10, textColor=CINZA,       spaceBefore=4,  spaceAfter=4,  leading=15, alignment=TA_JUSTIFY)
S_BULLET   = st('sBullet',   fontSize=10, textColor=CINZA,       spaceBefore=2,  spaceAfter=2,  leading=14, leftIndent=18, bulletIndent=6)
S_CODE     = st('sCode',     fontSize=8.5,textColor=colors.HexColor('#1e293b'), fontName='Courier',
                backColor=CINZA_LIGHT, spaceBefore=6, spaceAfter=6, leading=13, leftIndent=12, rightIndent=12)
S_BADGE    = st('sBadge',    fontSize=9,  textColor=BRANCO,      alignment=TA_CENTER, fontName='Helvetica-Bold')
S_TOC_H    = st('sTocH',     fontSize=13, textColor=AZUL,        fontName='Helvetica-Bold', spaceAfter=8)
S_TOC_ITEM = st('sTocItem',  fontSize=10, textColor=CINZA,       spaceBefore=3, spaceAfter=3, leftIndent=12)
S_MONO     = st('sMono',     fontSize=9,  textColor=AZUL,        fontName='Courier', leading=14)

def section_header(num, title):
    data = [[Paragraph(f'<font color="white"><b>Secao {num}</b></font>', S_BADGE),
             Paragraph(f'<font color="white"><b>{title}</b></font>',
                       ParagraphStyle('sh', fontSize=13, textColor=BRANCO,
                                      fontName='Helvetica-Bold', leading=18))]]
    t = Table(data, colWidths=[2.2*cm, 14.3*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), AZUL),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING',(0,0), (-1,-1), 10),
        ('RIGHTPADDING',(0,0),(-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING',(0,0),(-1,-1), 10),
    ]))
    return [Spacer(1, 10), t, Spacer(1, 10)]

def info_box(text, color=CINZA_LIGHT, border=AZUL_LIGHT):
    t = Table([[Paragraph(text, S_BODY)]], colWidths=[16.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), color),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LINEAFTER', (0,0), (0,-1), 3, border),
        ('GRID', (0,0), (-1,-1), 0, colors.transparent),
    ]))
    return [t, Spacer(1, 6)]

def code_block(lines):
    text = '<br/>'.join(lines)
    t = Table([[Paragraph(text, S_CODE)]], colWidths=[16.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), CINZA_LIGHT),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LINEAFTER', (0,0), (0,-1), 3, ROXO),
        ('BOX', (0,0), (-1,-1), 0.5, CINZA_MED),
    ]))
    return [t, Spacer(1, 6)]

def mk_table(headers, rows, col_widths, header_bg=AZUL):
    data = [[Paragraph(f'<b>{h}</b>', ParagraphStyle('th', fontSize=9, textColor=BRANCO,
             fontName='Helvetica-Bold', alignment=TA_CENTER)) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(c), ParagraphStyle('td', fontSize=9, textColor=CINZA,
                    alignment=TA_LEFT, leading=13)) for c in row])
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), header_bg),
        ('TEXTCOLOR',  (0,0), (-1,0), BRANCO),
        ('ALIGN',      (0,0), (-1,-1), 'LEFT'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING',(0,0),(-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BRANCO, CINZA_LIGHT]),
        ('GRID',       (0,0), (-1,-1), 0.4, CINZA_MED),
        ('BOX',        (0,0), (-1,-1), 1, AZUL),
    ]))
    return [t, Spacer(1, 8)]

def bullet(text):
    return Paragraph(f'<bullet>&bull;</bullet> {text}', S_BULLET)

def arch_box(label, sublabel, color=AZUL, width=16.5*cm):
    """Bloco visual de componente de arquitetura."""
    t = Table([[
        Paragraph(f'<b>{label}</b>', ParagraphStyle('ab', fontSize=11, textColor=BRANCO,
                  fontName='Helvetica-Bold', alignment=TA_CENTER, leading=16)),
        Paragraph(sublabel, ParagraphStyle('as', fontSize=8, textColor=colors.HexColor('#cbd5e1'),
                  alignment=TA_CENTER, leading=12)),
    ]], colWidths=[width*0.4, width*0.6])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), color),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
    ]))
    return t

def arrow_down():
    t = Table([[Paragraph('&#9660;', ParagraphStyle('arr', fontSize=16, textColor=AZUL_LIGHT,
                alignment=TA_CENTER))]], colWidths=[16.5*cm])
    t.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER')]))
    return [t, Spacer(1,2)]

def adr_box(num, title, status, context, decision, consequencias):
    """Architecture Decision Record box."""
    status_color = VERDE if status == 'Aceita' else LARANJA
    rows = [
        [Paragraph(f'<b>ADR-{num:02d}</b>', ParagraphStyle('an', fontSize=10, textColor=AZUL_LIGHT,
                   fontName='Helvetica-Bold')),
         Paragraph(f'<b>{title}</b>', ParagraphStyle('at', fontSize=10, textColor=AZUL,
                   fontName='Helvetica-Bold')),
         Paragraph(status, ParagraphStyle('as2', fontSize=9, textColor=BRANCO,
                   fontName='Helvetica-Bold', alignment=TA_CENTER))],
        [Paragraph('<b>Contexto</b>', ParagraphStyle('lbl', fontSize=8, textColor=CINZA,
                   fontName='Helvetica-Bold')),
         Paragraph(context, ParagraphStyle('ctx', fontSize=9, textColor=CINZA, leading=13)),
         Paragraph('')],
        [Paragraph('<b>Decisao</b>', ParagraphStyle('lbl2', fontSize=8, textColor=CINZA,
                   fontName='Helvetica-Bold')),
         Paragraph(decision, ParagraphStyle('dec', fontSize=9, textColor=AZUL, leading=13,
                   fontName='Helvetica-Bold')),
         Paragraph('')],
        [Paragraph('<b>Consequencias</b>', ParagraphStyle('lbl3', fontSize=8, textColor=CINZA,
                   fontName='Helvetica-Bold')),
         Paragraph(consequencias, ParagraphStyle('con', fontSize=9, textColor=CINZA, leading=13)),
         Paragraph('')],
    ]
    t = Table(rows, colWidths=[3*cm, 10.5*cm, 3*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), CINZA_LIGHT),
        ('BACKGROUND', (2,0), (2,0), status_color),
        ('SPAN',       (1,1), (2,1)),
        ('SPAN',       (1,2), (2,2)),
        ('SPAN',       (1,3), (2,3)),
        ('VALIGN',     (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('GRID',       (0,0), (-1,-1), 0.3, CINZA_MED),
        ('BOX',        (0,0), (-1,-1), 1, AZUL),
    ]))
    return [t, Spacer(1, 10)]

# ── CAPA ──────────────────────────────────────────────────────────────────────
def build_cover():
    cover = Table(
        [[Paragraph('&#9881;', ParagraphStyle('ico', fontSize=60, textColor=BRANCO, alignment=TA_CENTER))],
         [Spacer(1, 20)],
         [Paragraph('Marina One', S_TITULO)],
         [Paragraph('Arquitetura do Sistema', S_SUB)],
         [Spacer(1, 30)],
         [HRFlowable(width='60%', color=colors.HexColor('#3b82f6'), thickness=2)],
         [Spacer(1, 30)],
         [Paragraph('SaaS Multi-Tenant com Railway + PostgreSQL', ParagraphStyle('mt', fontSize=16, textColor=BRANCO,
                    alignment=TA_CENTER, fontName='Helvetica-Bold', leading=24))],
         [Spacer(1, 16)],
         [Paragraph('Versao 2.0 &nbsp;&middot;&nbsp; 2026', S_VERSION)],
        ],
        colWidths=[16.5*cm]
    )
    cover.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), AZUL),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING',(0,0),(-1,-1), 0),
        ('LEFTPADDING', (0,0), (-1,-1), 30),
        ('RIGHTPADDING', (0,0), (-1,-1), 30),
    ]))
    page_cover = Table([[cover]], colWidths=[16.5*cm], rowHeights=[22*cm])
    page_cover.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), AZUL),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
    ]))
    return [page_cover, PageBreak()]

def build_toc():
    secoes = [
        ('1', 'Visao Geral da Arquitetura'),
        ('2', 'Fluxo de Requisicao HTTP'),
        ('3', 'Multi-Tenancy — Schema per Tenant'),
        ('4', 'Camadas do Sistema'),
        ('5', 'Pipeline CI/CD'),
        ('6', 'Seguranca e Autenticacao'),
        ('7', 'Architecture Decision Records (ADRs)'),
        ('8', 'Evolucao e Roadmap'),
    ]
    elems = [Paragraph('Sumario', S_TOC_H),
             HRFlowable(width='100%', color=AZUL_LIGHT, thickness=1),
             Spacer(1, 12)]
    for num, title in secoes:
        row = Table([[
            Paragraph(f'<b>Secao {num}</b>', ParagraphStyle('tn', fontSize=10, textColor=AZUL_LIGHT, fontName='Helvetica-Bold')),
            Paragraph(title, S_TOC_ITEM),
        ]], colWidths=[2.5*cm, 14*cm])
        row.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LINEBELOW', (0,0), (-1,-1), 0.3, CINZA_MED),
        ]))
        elems.append(row)
    elems.append(PageBreak())
    return elems

def build_body():
    E = []

    # ── S1 — VISAO GERAL ────────────────────────────────────────────────────
    E += section_header('1', 'Visao Geral da Arquitetura')
    E += info_box(
        '<b>Marina One v2.0</b> e uma aplicacao SaaS multi-tenant monolitica (modular). '
        'Um unico processo Node.js serve todos os tenants. O isolamento de dados e '
        'garantido por schemas PostgreSQL separados por tenant. '
        'O deploy e automatico via GitHub > Railway.'
    )

    # Diagrama em ASCII-table
    E.append(Paragraph('<b>Visao de Alto Nivel</b>', S_H2))

    layers = [
        (colors.HexColor('#1e40af'), 'USUARIO FINAL', 'Navegador Web / Mobile'),
        (colors.HexColor('#1d4ed8'), 'CLOUDFLARE', 'DNS Wildcard + CDN + SSL/TLS'),
        (AZUL_LIGHT, 'RAILWAY (PaaS)', 'Hospedagem gerenciada — Node.js via Dockerfile'),
        (colors.HexColor('#0f766e'), 'NODE.JS APP', 'server.js — HTTP Server — Middleware — Rotas'),
        (colors.HexColor('#065f46'), 'POSTGRESQL', 'Schema saas + marina_<slug> por tenant'),
    ]
    for color, label, sub in layers:
        E.append(arch_box(label, sub, color=color))
        if label != 'POSTGRESQL':
            E += arrow_down()
    E.append(Spacer(1, 10))
    E.append(PageBreak())

    # ── S2 — FLUXO DE REQUISICAO ────────────────────────────────────────────
    E += section_header('2', 'Fluxo de Requisicao HTTP')
    E += info_box('Cada request passa por <b>resolucao de tenant</b> antes de qualquer '
                  'logica de negocio. O tenant determina qual schema PostgreSQL sera usado.')

    E.append(Paragraph('<b>Sequencia completa de um request</b>', S_H2))
    req_steps = [
        ('Browser', 'porto-belo.marinaone.com.br/api/clients', 'Subdominio como identificador de tenant'),
        ('Cloudflare', 'CNAME wildcard > Railway', 'DNS only, sem proxy — Railway gerencia SSL'),
        ('Railway', 'Roteamento para porta 3000', 'Balanceamento e health check'),
        ('tenant.js', 'Extrai slug do subdominio', 'porto-belo.marinaone.com.br > slug=porto-belo'),
        ('auth.js', 'Valida JWT Bearer token', 'Verifica assinatura e expiracao'),
        ('compat.js', 'SET search_path=marina_porto-belo', 'Todas as queries vao para o schema correto'),
        ('Route handler', 'Executa logica de negocio', 'SELECT * FROM clients (schema isolado)'),
        ('Response', 'JSON para o browser', 'Dados exclusivos deste tenant'),
    ]
    E += mk_table(
        ['Etapa', 'Acao', 'Detalhe'],
        req_steps,
        [2.5*cm, 5.5*cm, 8.5*cm]
    )

    E.append(Paragraph('<b>Resolucao de Tenant — Ordem de Prioridade</b>', S_H2))
    E += code_block([
        '1. Header X-Tenant-Slug: porto-belo        (NGINX/Cloudflare)',
        '2. Subdominio: porto-belo.marinaone.com.br  (mais comum)',
        '3. Query string: ?tenant=porto-belo          (fallback)',
        '4. ENV SINGLE_TENANT_SLUG=demo               (modo local)',
    ])
    E.append(PageBreak())

    # ── S3 — MULTI-TENANCY ──────────────────────────────────────────────────
    E += section_header('3', 'Multi-Tenancy - Schema per Tenant')
    E += info_box(
        '<b>Padrao escolhido: Schema-per-Tenant.</b> '
        'Cada marina tem seu proprio schema PostgreSQL (<b>marina_&lt;slug&gt;</b>). '
        'Isolamento total dos dados — nenhuma marina pode acessar dados de outra. '
        'O schema <b>saas</b> e global e gerencia os tenants.'
    )

    E.append(Paragraph('<b>Estrutura de Schemas no PostgreSQL</b>', S_H2))
    E += code_block([
        'PostgreSQL (Railway)',
        '├── schema: saas                    # Global - gerenciado pelo superadmin',
        '│   ├── tenants                     # Lista de todas as marinas',
        '│   └── super_admins               # Administradores globais',
        '│',
        '├── schema: marina_demo             # Tenant local de desenvolvimento',
        '│   ├── users, clients, boats',
        '│   ├── spots, contracts, financial',
        '│   └── queue, shop, maintenance',
        '│',
        '├── schema: marina_porto-belo       # Marina Porto Belo (producao)',
        '│   └── (mesmas tabelas)',
        '│',
        '└── schema: marina_santos           # Marina Santos (producao)',
        '    └── (mesmas tabelas)',
    ])

    E.append(Paragraph('<b>Comparacao de Estrategias de Multi-Tenancy</b>', S_H2))
    E += mk_table(
        ['Estrategia', 'Isolamento', 'Complexidade', 'Escolhida?'],
        [
            ['Banco separado por tenant', 'Maximo', 'Alta (muitas conexoes)', 'Nao'],
            ['Schema por tenant (atual)', 'Alto', 'Media', 'SIM'],
            ['Coluna tenant_id', 'Baixo (logico)', 'Baixa', 'Nao'],
        ],
        [5.5*cm, 3.5*cm, 4*cm, 3.5*cm]
    )

    E.append(Paragraph('<b>Provisionamento de Novo Tenant</b>', S_H2))
    E += code_block([
        '# Criar novo tenant via API super-admin:',
        'POST /api/superadmin/tenants',
        '{',
        '  "slug": "novo-tenant",',
        '  "marinaName": "Marina Novo Tenant",',
        '  "adminEmail": "admin@novotenant.com"',
        '}',
        '',
        '# O sistema automaticamente:',
        '# 1. Cria registro em saas.tenants',
        '# 2. Cria schema marina_novo-tenant',
        '# 3. Executa todas as migrations no novo schema',
        '# 4. Cria usuario admin inicial',
    ])
    E.append(PageBreak())

    # ── S4 — CAMADAS ────────────────────────────────────────────────────────
    E += section_header('4', 'Camadas do Sistema')

    E.append(Paragraph('<b>Camada de Apresentacao (Frontend)</b>', S_H2))
    E += info_box('SPA (Single Page Application) em HTML/CSS/JS puro, sem framework. '
                  'Servido pelo proprio Node.js como arquivo estatico. '
                  'Comunicacao com backend via fetch() + JSON. Graficos com Chart.js (CDN).')
    E += mk_table(
        ['Modulo UI', 'Descricao'],
        [
            ['Dashboard', 'KPIs, graficos de ocupacao, alertas em tempo real'],
            ['Fila de Operacoes', 'Entrada/saida de embarcacoes, movimentacao'],
            ['Clientes / Embarcacoes', 'Cadastro completo com historico'],
            ['Contratos', 'Gestao de contratos de permanencia e avulsos'],
            ['Financeiro', 'Lancamentos, contas a receber/pagar, relatorios'],
            ['Loja / PDV', 'Venda de produtos e servicos na marina'],
            ['Manutencao', 'Ordens de servico e historico de manutencoes'],
            ['Super-Admin', 'Painel exclusivo para gestao de todos os tenants'],
        ],
        [5*cm, 11.5*cm]
    )

    E.append(Paragraph('<b>Camada de Aplicacao (Backend)</b>', S_H2))
    E += mk_table(
        ['Arquivo', 'Responsabilidade'],
        [
            ['server.js', 'HTTP server, registro de rotas, startup, health check'],
            ['src/middleware/auth.js', 'JWT: geracao, validacao, hashing de senhas (SHA-256)'],
            ['src/middleware/tenant.js', 'Resolucao do tenant por request (header/subdominio/query)'],
            ['src/db/pool.js', 'Pool de conexoes PostgreSQL com SSL'],
            ['src/db/compat.js', 'Helpers dbAll/dbGet/dbRun com SET search_path automatico'],
            ['src/db/migrate.js', 'Migrations e provisionamento de schemas por tenant'],
        ],
        [5.5*cm, 11*cm]
    )
    E.append(PageBreak())

    # ── S5 — CI/CD ──────────────────────────────────────────────────────────
    E += section_header('5', 'Pipeline CI/CD')
    E += info_box('<b>Deploy automatico:</b> qualquer push na branch main aciona o Railway, '
                  'que rebuilda a imagem Docker e substitui o container em producao. '
                  'Zero downtime com health check configurado.')

    E.append(Paragraph('<b>Fluxo de Deploy</b>', S_H2))
    deploy_flow = [
        ('Desenvolvedor', 'publicar.bat "descricao"', 'Bump versao, commit, tag, push'),
        ('GitHub', 'Recebe o push na branch main', 'Webhook notifica o Railway'),
        ('Railway', 'Clona repositorio', 'Detecta mudanca na branch main'),
        ('Railway', 'docker build -f Dockerfile', 'Build da imagem Node.js 20 Alpine'),
        ('Railway', 'Health check: GET /api/version', 'Aguarda 200 OK (timeout 30s)'),
        ('Railway', 'Substitui container antigo', 'Zero downtime — novo container ativo'),
        ('Railway', 'Deploy completo', 'Logs disponiveis: railway logs'),
    ]
    E += mk_table(
        ['Agente', 'Acao', 'Detalhe'],
        deploy_flow,
        [3*cm, 5.5*cm, 8*cm]
    )

    E.append(Paragraph('<b>Dockerfile de Producao</b>', S_H2))
    E += code_block([
        'FROM node:20-alpine',
        'WORKDIR /app',
        'COPY package*.json ./',
        'RUN npm install --production',
        'COPY . .',
        'EXPOSE 3000',
        'CMD ["node", "server.js"]',
    ])

    E.append(Paragraph('<b>railway.json — Configuracao de Deploy</b>', S_H2))
    E += code_block([
        '{',
        '  "build": { "builder": "DOCKERFILE" },',
        '  "deploy": {',
        '    "startCommand": "node server.js",',
        '    "healthcheckPath": "/api/version",',
        '    "healthcheckTimeout": 30,',
        '    "restartPolicyType": "ON_FAILURE",',
        '    "restartPolicyMaxRetries": 3',
        '  }',
        '}',
    ])
    E.append(PageBreak())

    # ── S6 — SEGURANCA ──────────────────────────────────────────────────────
    E += section_header('6', 'Seguranca e Autenticacao')

    E.append(Paragraph('<b>Autenticacao JWT</b>', S_H2))
    E += mk_table(
        ['Aspecto', 'Implementacao'],
        [
            ['Algoritmo', 'HS256 (HMAC-SHA256) com JWT_SECRET no env'],
            ['Expiracao', '24 horas por token'],
            ['Hash de senha', 'SHA-256 com salt (sem bcrypt para manter legado)'],
            ['Armazenamento', 'localStorage no browser (token Bearer)'],
            ['Renovacao', 'Re-login apos expiracao'],
        ],
        [4*cm, 12.5*cm]
    )

    E.append(Paragraph('<b>Isolamento de Tenants</b>', S_H2))
    E += mk_table(
        ['Mecanismo', 'Como Funciona'],
        [
            ['SET search_path', 'Cada query executa no schema do tenant — impossivel cruzar dados'],
            ['JWT por tenant', 'Token contem o slug do tenant — validado a cada request'],
            ['Super-admin separado', 'JWT diferente, rota /api/superadmin/* com middleware proprio'],
            ['SSL obrigatorio', 'DB_SSL=true — conexao PostgreSQL sempre criptografada'],
        ],
        [4.5*cm, 12*cm]
    )

    E.append(Paragraph('<b>Variaveis Sensiveis (nunca no codigo)</b>', S_H2))
    E += code_block([
        '# Apenas em Railway environment variables:',
        'DATABASE_URL   # URL completa com credenciais do PostgreSQL',
        'JWT_SECRET     # Chave para assinar tokens JWT',
        '',
        '# Nunca em:',
        '# - codigo fonte (server.js, .js)',
        '# - arquivos de configuracao versionados',
        '# - CHANGELOG.md ou comentarios',
    ])
    E.append(PageBreak())

    # ── S7 — ADRS ────────────────────────────────────────────────────────────
    E += section_header('7', 'Architecture Decision Records (ADRs)')
    E += info_box('ADRs documentam decisoes arquiteturais importantes, seu contexto e consequencias. '
                  'Servem como referencia para futuras decisoes e onboarding de novos desenvolvedores.')

    E += adr_box(
        1, 'PostgreSQL com schema-per-tenant', 'Aceita',
        'Sistema precisa suportar multiplas marinas com dados completamente isolados.',
        'Usar PostgreSQL com um schema por tenant (marina_<slug>) em vez de banco separado ou coluna tenant_id.',
        'Isolamento forte, backup por schema possivel, migracao mais simples que banco separado. '
        'Custo: maior complexidade no ORM e nas queries. Limite pratico: ~100 tenants por instancia.'
    )

    E += adr_box(
        2, 'Node.js monolito modular (sem microservicos)', 'Aceita',
        'Time pequeno, necessidade de deploy simples, sem complexidade operacional de microsservicos.',
        'Manter arquitetura monolitica modular em Node.js. Modularizar por feature, nao por servico.',
        'Deploy simples, debugging direto, sem latencia de rede entre servicos. '
        'Custo: escala vertical (nao horizontal por servico). Adequado para o porte atual.'
    )

    E += adr_box(
        3, 'Railway como plataforma de deploy (PaaS)', 'Aceita',
        'Necessidade de deploy rapido sem gestao de infraestrutura (VPS, Kubernetes, etc.).',
        'Usar Railway com Dockerfile + PostgreSQL gerenciado. Deploy via git push.',
        'Zero gestao de servidor, deploy automatico, PostgreSQL incluso. '
        'Custo: lock-in com Railway, limite de dominios customizados no plano Hobby (2 dominios).'
    )

    E += adr_box(
        4, 'Frontend SPA em HTML/CSS/JS puro (sem framework)', 'Aceita',
        'Reduzir dependencias, simplificar build, facilitar manutencao por time pequeno.',
        'Nao usar React/Vue/Angular. Frontend em HTML5 + CSS3 + JS vanilla, servido pelo Node.js.',
        'Zero build step, zero node_modules no frontend, carregamento rapido. '
        'Custo: sem componentizacao automatica, mais codigo repetido em UI complexa.'
    )

    E.append(PageBreak())

    # ── S8 — ROADMAP ────────────────────────────────────────────────────────
    E += section_header('8', 'Evolucao e Roadmap')

    E.append(Paragraph('<b>Versoes Anteriores</b>', S_H2))
    E += mk_table(
        ['Versao', 'Caracteristica Principal', 'Status'],
        [
            ['v1.x', 'Single-tenant, SQLite, deploy VPS via NGINX + PM2', 'Legado'],
            ['v2.0', 'Multi-tenant SaaS, PostgreSQL, Railway, subdominios', 'Atual'],
        ],
        [2.5*cm, 10*cm, 4*cm]
    )

    E.append(Paragraph('<b>Proximos Passos (Roadmap)</b>', S_H2))
    E += mk_table(
        ['Prioridade', 'Item', 'Descricao'],
        [
            ['Alta', 'Notificacoes push', 'Alertas de vencimento de contrato e manutencao'],
            ['Alta', 'Relatorios PDF', 'Exportacao de relatorios financeiros e operacionais'],
            ['Media', 'Integracao PIX', 'Pagamentos online para contratos e servicos'],
            ['Media', 'App mobile', 'PWA ou React Native para operadores em campo'],
            ['Baixa', 'Redis cache', 'Cache de sessao e consultas frequentes'],
            ['Baixa', 'Webhooks', 'Integracao com sistemas externos (ERP, contabilidade)'],
        ],
        [2.5*cm, 4.5*cm, 9.5*cm]
    )

    E.append(Paragraph('<b>Quando Escalar a Infraestrutura</b>', S_H2))
    E += mk_table(
        ['Indicador', 'Threshold', 'Acao Recomendada'],
        [
            ['Usuarios simultaneos', '> 50', 'Railway Pro (US$ 20/mes) + mais RAM'],
            ['Numero de tenants', '> 20 marinas', 'Avaliar read replicas PostgreSQL'],
            ['Tempo de resposta API', '> 500ms', 'Adicionar Redis para cache'],
            ['Storage PostgreSQL', '> 5 GB', 'Upgrade do plano Railway'],
        ],
        [4.5*cm, 3.5*cm, 8.5*cm]
    )

    E.append(Spacer(1, 15))
    contact = Table([
        [Paragraph('<b>Arthur Noli</b>', ParagraphStyle('cn', fontSize=13, textColor=AZUL,
                   fontName='Helvetica-Bold'))],
        [Paragraph('Arquiteto de Software | Marina One', S_BODY)],
        [Spacer(1,6)],
        [Paragraph('&#9993; rj.madmax@gmail.com', ParagraphStyle('ce', fontSize=11,
                   textColor=AZUL_LIGHT, fontName='Helvetica-Bold'))],
    ], colWidths=[16.5*cm])
    contact.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), CINZA_LIGHT),
        ('LEFTPADDING', (0,0), (-1,-1), 20),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LINEBEFORE', (0,0), (0,-1), 4, AZUL),
    ]))
    E.append(contact)
    return E

# ── PAGE TEMPLATE ─────────────────────────────────────────────────────────────
def on_first_page(canvas, doc):
    pass

def on_later_pages(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(AZUL)
    canvas.rect(0, H - 1*cm, W, 1*cm, fill=1, stroke=0)
    canvas.setFillColor(BRANCO)
    canvas.setFont('Helvetica-Bold', 9)
    canvas.drawString(2*cm, H - 0.65*cm, 'Marina One - Arquitetura do Sistema')
    canvas.setFont('Helvetica', 9)
    canvas.drawRightString(W - 2*cm, H - 0.65*cm, 'Versao 2.0 - 2026')
    canvas.setFillColor(CINZA)
    canvas.setFont('Helvetica', 8)
    canvas.drawCentredString(W/2, 0.7*cm, f'Pagina {doc.page}')
    canvas.setFillColor(CINZA_LIGHT)
    canvas.rect(2*cm, 0.5*cm, W - 4*cm, 0.02*cm, fill=1, stroke=0)
    canvas.restoreState()

# ── BUILD ─────────────────────────────────────────────────────────────────────
def main():
    doc = SimpleDocTemplate(
        OUT, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        title='Arquitetura - Marina One',
        author='Arthur Noli',
        subject='Documento de arquitetura do sistema SaaS Marina One',
    )
    story = build_cover() + build_toc() + build_body()
    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    print(f'PDF gerado: {OUT}')

if __name__ == '__main__':
    main()
