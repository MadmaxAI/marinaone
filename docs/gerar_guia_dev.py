
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

W, H = A4
OUT  = os.path.join(os.path.dirname(__file__), 'Guia de Desenvolvimento Marina One.pdf')

# ── ESTILOS ───────────────────────────────────────────────────────────────────
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

# ── HELPERS ───────────────────────────────────────────────────────────────────
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

def warn_box(text):
    return info_box(text, color=colors.HexColor('#fffbeb'), border=LARANJA)

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

def step_block(num, title, lines):
    elems = [Paragraph(f'<b>Passo {num} - {title}</b>', S_H2)]
    elems += code_block(lines)
    return elems

def flow_step(num, label, detail=''):
    bg = AZUL if num % 2 == 1 else AZUL_LIGHT
    row = [[
        Paragraph(f'<font color="white"><b>{num}</b></font>',
                  ParagraphStyle('fn', fontSize=11, textColor=BRANCO, alignment=TA_CENTER, fontName='Helvetica-Bold')),
        Paragraph(f'<b>{label}</b>' + (f'<br/><font size="8" color="#94a3b8">{detail}</font>' if detail else ''),
                  ParagraphStyle('fl', fontSize=10, textColor=AZUL, fontName='Helvetica-Bold', leading=14)),
    ]]
    t = Table(row, colWidths=[1.2*cm, 15.3*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), bg),
        ('BACKGROUND', (1,0), (1,-1), CINZA_LIGHT),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING',(0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING',(0,0),(-1,-1), 8),
        ('LINEBELOW',  (0,0), (-1,-1), 0.3, CINZA_MED),
    ]))
    return t

# ── CAPA ──────────────────────────────────────────────────────────────────────
def build_cover():
    cover = Table(
        [[Paragraph('&#128736;', ParagraphStyle('ico', fontSize=60, textColor=BRANCO, alignment=TA_CENTER))],
         [Spacer(1, 20)],
         [Paragraph('Marina One', S_TITULO)],
         [Paragraph('Guia de Desenvolvimento', S_SUB)],
         [Spacer(1, 30)],
         [HRFlowable(width='60%', color=colors.HexColor('#3b82f6'), thickness=2)],
         [Spacer(1, 30)],
         [Paragraph('Fluxo completo: local -> teste -> producao', ParagraphStyle('mt', fontSize=16, textColor=BRANCO,
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

# ── SUMARIO ───────────────────────────────────────────────────────────────────
def build_toc():
    secoes = [
        ('1', 'Ambientes e Stack'),
        ('2', 'Configuracao do Ambiente Local'),
        ('3', 'Fluxo de Desenvolvimento'),
        ('4', 'Comandos Essenciais'),
        ('5', 'Estrutura do Projeto'),
        ('6', 'Banco de Dados'),
        ('7', 'API - Rotas Principais'),
        ('8', 'Versionamento e Publicacao'),
        ('9', 'Troubleshooting'),
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

# ── CONTEUDO ──────────────────────────────────────────────────────────────────
def build_body():
    E = []

    # ── S1 — AMBIENTES ──────────────────────────────────────────────────────
    E += section_header('1', 'Ambientes e Stack')
    E += mk_table(
        ['Ambiente', 'URL', 'Banco', 'Tenant'],
        [
            ['Local (Docker)', 'http://localhost:3000', 'marinaone_db (Docker)', 'SINGLE_TENANT_SLUG=demo'],
            ['Producao (Railway)', 'https://marina-one-app.up.railway.app', 'PostgreSQL Railway', '?tenant=slug ou subdominio'],
        ],
        [3.5*cm, 5*cm, 4.5*cm, 3.5*cm]
    )

    E.append(Paragraph('<b>Stack Completo</b>', S_H2))
    E += mk_table(
        ['Camada', 'Tecnologia', 'Versao'],
        [
            ['Runtime', 'Node.js', 'v20 LTS'],
            ['Banco de dados', 'PostgreSQL', '16'],
            ['Driver DB', 'postgres.js', '3.x'],
            ['Frontend', 'HTML5 + CSS3 + JS puro', '-'],
            ['Graficos', 'Chart.js', 'CDN'],
            ['Container local', 'Docker + Docker Compose', '-'],
            ['Deploy', 'Railway (Dockerfile)', '-'],
            ['CI/CD', 'GitHub > Railway auto-deploy', '-'],
            ['DNS/CDN', 'Cloudflare', 'Free'],
        ],
        [4*cm, 7*cm, 5.5*cm]
    )
    E.append(PageBreak())

    # ── S2 — AMBIENTE LOCAL ─────────────────────────────────────────────────
    E += section_header('2', 'Configuracao do Ambiente Local')
    E += info_box('<b>Pre-requisitos:</b> Node.js v20+, Docker Desktop instalado e rodando, Git.')

    E += step_block('1', 'Clonar o projeto',
        ['git clone https://github.com/MadmaxAI/marinaone.git',
         'cd marinaone'])

    E += step_block('2', 'Subir o ambiente local',
        ['docker compose up -d'])

    E += step_block('3', 'Verificar containers',
        ['docker ps',
         '# Deve mostrar marinaone_app e marinaone_db rodando'])

    E += step_block('4', 'Acessar o sistema',
        ['http://localhost:3000',
         '# Login padrao: admin@marina.com / marina123'])

    E.append(Paragraph('<b>Variaveis do ambiente local (docker-compose.yml)</b>', S_H2))
    E += code_block([
        'DATABASE_URL=postgres://marinaone:marina_dev_2025@db:5432/marinaone',
        'NODE_ENV=production',
        'JWT_SECRET=marina_dev_jwt_secret_2025',
        'SINGLE_TENANT_SLUG=demo',
        'BASE_DOMAIN=localhost',
    ])
    E.append(PageBreak())

    # ── S3 — FLUXO DE DESENVOLVIMENTO ───────────────────────────────────────
    E += section_header('3', 'Fluxo de Desenvolvimento')
    E += warn_box('<b>REGRA PRINCIPAL:</b> Nunca publicar em producao sem aprovacao explicita. '
                  'O Claude Code aguarda o usuario dizer "aprovado" antes de rodar publicar.bat.')

    E.append(Paragraph('<b>Fluxo Obrigatorio</b>', S_H2))
    steps = [
        ('Solicitar alteracao ao Claude Code', 'Descricao do que deve ser mudado/corrigido'),
        ('Claude altera os arquivos', 'Edicoes em server.js, frontend.html, etc.'),
        ('Claude executa testar.bat', 'Rebuild Docker + restart container app'),
        ('Desenvolvedor testa localhost:3000', 'Verificar funcionalidade no navegador'),
        ('Dizer "aprovado" ao Claude', 'Ou: "ok", "pode publicar", "publish", "deploy"'),
        ('Claude executa publicar.bat', 'Bump versao, commit, tag, push GitHub'),
        ('Railway detecta o push', 'Deploy automatico iniciado em ~2 minutos'),
        ('Verificar em producao', '/api/version mostra nova versao'),
    ]
    for i, (label, detail) in enumerate(steps, 1):
        E.append(flow_step(i, label, detail))
        E.append(Spacer(1, 2))

    E.append(Spacer(1, 10))
    E.append(Paragraph('<b>Comandos de apoio durante teste local</b>', S_H2))
    E += code_block([
        'testar.bat                        # Rebuild + reinicia o container',
        'docker logs marinaone_app -f      # Ver logs em tempo real',
        'docker exec -it marinaone_app sh  # Entrar no container',
    ])
    E.append(PageBreak())

    # ── S4 — COMANDOS ────────────────────────────────────────────────────────
    E += section_header('4', 'Comandos Essenciais')

    E.append(Paragraph('<b>Docker - Gerenciamento de Containers</b>', S_H2))
    E += mk_table(
        ['Comando', 'Descricao'],
        [
            ['docker compose up -d', 'Subir todos os servicos (app + banco)'],
            ['docker compose down', 'Parar todos os servicos'],
            ['docker restart marinaone_app', 'Reiniciar apenas o app'],
            ['docker logs marinaone_app -f', 'Ver logs ao vivo'],
            ['docker exec -it marinaone_db psql -U marinaone', 'Acessar PostgreSQL local'],
            ['testar.bat', 'Rebuild + restart (apos alteracoes de codigo)'],
        ],
        [8*cm, 8.5*cm]
    )

    E.append(Paragraph('<b>Railway CLI - Gerenciamento de Producao</b>', S_H2))
    E += mk_table(
        ['Comando', 'Descricao'],
        [
            ['railway whoami', 'Verificar conta logada'],
            ['railway logs', 'Ver logs de producao em tempo real'],
            ['railway variables', 'Listar variaveis de ambiente'],
            ['railway up --service marina-one-app', 'Deploy manual (emergencia)'],
            ['railway service status', 'Status atual do servico'],
        ],
        [8*cm, 8.5*cm]
    )

    E.append(Paragraph('<b>Git / Versionamento Semantico</b>', S_H2))
    E += mk_table(
        ['Comando', 'Efeito'],
        [
            ['publicar.bat "msg"', 'Patch: 2.0.3 > 2.0.4 (correcao de bug)'],
            ['publicar.bat "msg" minor', 'Minor: 2.0.x > 2.1.0 (nova funcionalidade)'],
            ['publicar.bat "msg" major', 'Major: 2.x > 3.0.0 (mudanca grande)'],
            ['git log --oneline -10', 'Historico das ultimas 10 versoes'],
            ['git tag --sort=-v:refname', 'Listar todas as tags de versao'],
        ],
        [8*cm, 8.5*cm]
    )
    E.append(PageBreak())

    # ── S5 — ESTRUTURA ────────────────────────────────────────────────────────
    E += section_header('5', 'Estrutura do Projeto')
    E += code_block([
        'marina-one/',
        '├── server.js              # Servidor principal (rotas, middleware, startup)',
        '├── frontend.html          # SPA completo (UI, JS, CSS inline)',
        '├── package.json           # Dependencias e versao',
        '├── Dockerfile             # Build para Railway (Node.js 20 Alpine)',
        '├── docker-compose.yml     # Ambiente local (app + PostgreSQL)',
        '├── railway.json           # Configuracao Railway (healthcheck, restart)',
        '├── CLAUDE.md              # Regras para o Claude Code',
        '├── CHANGELOG.md           # Historico de versoes',
        '├── publicar.bat           # Script de publicacao Windows',
        '├── testar.bat             # Script de teste local',
        '├── src/',
        '│   ├── db/',
        '│   │   ├── pool.js        # Gerenciamento de conexoes PostgreSQL',
        '│   │   ├── compat.js      # Camada SQLite>PostgreSQL (dbAll/dbGet/dbRun)',
        '│   │   ├── migrate.js     # Migrations e provisionamento de tenants',
        '│   │   └── saas_schema.sql  # Schema global "saas"',
        '│   └── middleware/',
        '│       ├── auth.js        # JWT, hashing, authMiddleware',
        '│       └── tenant.js      # Resolucao de tenant por request',
        '└── docs/',
        '    ├── Manual de Implantacao Marina One.pdf',
        '    ├── Guia de Desenvolvimento Marina One.pdf',
        '    └── Arquitetura Marina One.pdf',
    ])
    E.append(PageBreak())

    # ── S6 — BANCO DE DADOS ──────────────────────────────────────────────────
    E += section_header('6', 'Banco de Dados')
    E += info_box('<b>Arquitetura schema-per-tenant:</b> cada marina possui seu proprio schema '
                  'PostgreSQL isolado (<b>marina_&lt;slug&gt;</b>). O schema <b>saas</b> e global '
                  'e armazena tenants e super_admins. Nenhuma marina acessa dados de outra.')

    E.append(Paragraph('<b>Helpers de Banco (src/db/compat.js)</b>', S_H2))
    E += code_block([
        'const { dbAll, dbGet, dbRun } = createDbHelpers(req.tenantSlug);',
        '',
        '// dbAll  - retorna array de linhas',
        "dbAll('SELECT * FROM clients WHERE active = $1', [true])",
        '',
        '// dbGet  - retorna uma linha ou null',
        "dbGet('SELECT * FROM clients WHERE id = $1', [id])",
        '',
        '// dbRun  - retorna { lastInsertRowid, changes }',
        "dbRun('INSERT INTO clients (name) VALUES ($1)', ['Joao'])",
    ])

    E.append(Paragraph('<b>Conversoes Automaticas (SQLite > PostgreSQL)</b>', S_H2))
    E += mk_table(
        ['SQLite (legado)', 'PostgreSQL (atual)'],
        [
            ['? (placeholder)', '$1, $2, $3 (numerados)'],
            ['INSERT OR IGNORE', 'INSERT ... ON CONFLICT DO NOTHING'],
            ["datetime('now')", 'NOW()'],
            ["strftime('%Y-%m-%d', col)", "TO_CHAR(col, 'YYYY-MM-DD')"],
            ['INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY'],
        ],
        [8*cm, 8.5*cm]
    )
    E.append(PageBreak())

    # ── S7 — API ──────────────────────────────────────────────────────────────
    E += section_header('7', 'API - Rotas Principais')

    E.append(Paragraph('<b>Rotas Publicas (sem autenticacao)</b>', S_H2))
    E += mk_table(
        ['Metodo', 'Rota', 'Descricao'],
        [
            ['GET', '/api/version', 'Health check e versao do sistema'],
            ['POST', '/api/auth/login', 'Login > retorna JWT'],
            ['POST', '/api/auth/logout', 'Logout'],
        ],
        [2*cm, 5*cm, 9.5*cm]
    )

    E.append(Paragraph('<b>Rotas Autenticadas (Bearer JWT)</b>', S_H2))
    E += mk_table(
        ['Metodo', 'Rota', 'Descricao'],
        [
            ['GET', '/api/dashboard', 'KPIs e dados do painel principal'],
            ['GET/POST', '/api/clients', 'Listar e criar clientes'],
            ['GET/POST', '/api/boats', 'Listar e criar embarcacoes'],
            ['GET/POST', '/api/spots', 'Vagas da marina'],
            ['GET/POST', '/api/contracts', 'Contratos de permanencia'],
            ['GET/POST', '/api/financial', 'Lancamentos financeiros'],
            ['GET/POST', '/api/queue', 'Fila de operacoes (entrada/saida)'],
            ['GET/POST', '/api/shop', 'Produtos e vendas PDV'],
            ['GET/POST', '/api/maintenance', 'Ordens de manutencao'],
            ['GET', '/api/analytics', 'Relatorios e graficos'],
        ],
        [2*cm, 5*cm, 9.5*cm]
    )

    E.append(Paragraph('<b>Rotas Super-Admin</b>', S_H2))
    E += mk_table(
        ['Metodo', 'Rota', 'Descricao'],
        [
            ['GET', '/api/superadmin/tenants', 'Listar todas as marinas'],
            ['POST', '/api/superadmin/tenants', 'Criar nova marina (provisionar schema)'],
            ['GET', '/api/superadmin/stats', 'Estatisticas globais de uso'],
            ['POST', '/api/superadmin/login', 'Login super-admin (JWT separado)'],
        ],
        [2*cm, 5.5*cm, 9*cm]
    )
    E.append(PageBreak())

    # ── S8 — VERSIONAMENTO ────────────────────────────────────────────────────
    E += section_header('8', 'Versionamento e Publicacao')
    E += info_box('<b>Versionamento semantico (SemVer):</b> MAJOR.MINOR.PATCH. '
                  'O script publicar.bat gerencia automaticamente o bump, '
                  'CHANGELOG.md, git tag e push.')

    E.append(Paragraph('<b>O que publicar.bat faz automaticamente</b>', S_H2))
    steps_pub = [
        ('Detecta alteracoes', 'git diff - verifica se ha mudancas para commitar'),
        ('Faz bump de versao', 'Atualiza package.json com nova versao SemVer'),
        ('Atualiza CHANGELOG.md', 'Insere entrada com versao, data e descricao'),
        ('Cria commit', 'git commit -m "vX.Y.Z: descricao"'),
        ('Cria tag Git', 'git tag "vX.Y.Z" com mensagem'),
        ('Push para GitHub', 'git push origin main && git push origin vX.Y.Z'),
        ('Railway deploya', 'Auto-detect do push > deploy em ~2 minutos'),
    ]
    for i, (label, detail) in enumerate(steps_pub, 1):
        E.append(flow_step(i, label, detail))
        E.append(Spacer(1, 2))

    E.append(Spacer(1, 10))
    E.append(Paragraph('<b>Exemplos de uso</b>', S_H2))
    E += code_block([
        '# Correcao de bug (patch: 2.0.3 > 2.0.4)',
        'publicar.bat "corrige calculo de contratos vencidos"',
        '',
        '# Nova funcionalidade (minor: 2.0.4 > 2.1.0)',
        'publicar.bat "adiciona relatorio de ocupacao mensal" minor',
        '',
        '# Mudanca grande (major: 2.1.0 > 3.0.0)',
        'publicar.bat "migra para nova arquitetura de eventos" major',
    ])
    E.append(PageBreak())

    # ── S9 — TROUBLESHOOTING ──────────────────────────────────────────────────
    E += section_header('9', 'Troubleshooting')

    problemas = [
        (
            'Container nao sobe / erro no docker compose up',
            ['docker compose down',
             'docker compose up -d --force-recreate',
             'docker logs marinaone_app  # verificar erro'],
        ),
        (
            'Mudancas de codigo nao aparecem no localhost',
            ['testar.bat  # Rebuild completo da imagem Docker',
             '# Aguardar ~30s e recarregar http://localhost:3000'],
        ),
        (
            'Erro de conexao com banco local',
            ['docker ps  # verificar se marinaone_db esta rodando',
             'docker restart marinaone_db',
             'docker restart marinaone_app'],
        ),
        (
            'publicar.bat nao detecta alteracoes',
            ['git status  # verificar estado dos arquivos',
             'git add .   # adicionar arquivos nao rastreados',
             'publicar.bat "descricao"  # tentar novamente'],
        ),
        (
            'Deploy Railway nao iniciou apos push',
            ['# Verificar no painel Railway > Deployments',
             '# Verificar GitHub > Settings > Installed Apps > Railway App',
             'railway logs  # ver logs de producao'],
        ),
        (
            'Erro 502 Bad Gateway na URL de producao',
            ['railway logs  # ver o erro real do servidor',
             '# Verificar variaveis DATABASE_URL, NODE_ENV, PORT',
             'railway variables  # listar todas as variaveis'],
        ),
    ]

    for problema, cmds in problemas:
        E.append(Paragraph(f'<b>Problema: {problema}</b>', S_H2))
        E += code_block(cmds)

    E.append(Spacer(1, 10))
    contact = Table([
        [Paragraph('<b>Suporte Tecnico</b>', ParagraphStyle('cn', fontSize=13, textColor=AZUL,
                   fontName='Helvetica-Bold'))],
        [Paragraph('Arthur Noli - Especialista em Sistemas de Gestao para Marinas', S_BODY)],
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
    canvas.drawString(2*cm, H - 0.65*cm, 'Marina One - Guia de Desenvolvimento')
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
        title='Guia de Desenvolvimento - Marina One',
        author='Arthur Noli',
        subject='Guia tecnico de desenvolvimento e deploy',
    )
    story = build_cover() + build_toc() + build_body()
    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    print(f'PDF gerado: {OUT}')

if __name__ == '__main__':
    main()
