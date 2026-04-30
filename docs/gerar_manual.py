
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
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ── CORES ────────────────────────────────────────────────────────────────────
AZUL       = colors.HexColor('#1e3a5f')
AZUL_LIGHT = colors.HexColor('#2563eb')
CINZA      = colors.HexColor('#475569')
CINZA_LIGHT= colors.HexColor('#f1f5f9')
CINZA_MED  = colors.HexColor('#e2e8f0')
BRANCO     = colors.white
VERDE      = colors.HexColor('#10b981')
LARANJA    = colors.HexColor('#f59e0b')

W, H = A4
OUT  = os.path.join(os.path.dirname(__file__), 'Manual de Implantacao Marina One.pdf')

# ── ESTILOS ───────────────────────────────────────────────────────────────────
styles = getSampleStyleSheet()

def st(name, parent='Normal', **kw):
    s = ParagraphStyle(name, parent=styles[parent], **kw)
    return s

S_TITULO   = st('sTitulo',   fontSize=32, textColor=BRANCO,     alignment=TA_CENTER, leading=40, spaceAfter=8)
S_SUB      = st('sSub',      fontSize=14, textColor=colors.HexColor('#93c5fd'), alignment=TA_CENTER, leading=20, spaceAfter=6)
S_VERSION  = st('sVersion',  fontSize=11, textColor=colors.HexColor('#cbd5e1'), alignment=TA_CENTER, leading=16)
S_H1       = st('sH1',       fontSize=16, textColor=AZUL,        spaceBefore=18, spaceAfter=8,  fontName='Helvetica-Bold', leading=22)
S_H2       = st('sH2',       fontSize=12, textColor=AZUL_LIGHT,  spaceBefore=12, spaceAfter=6,  fontName='Helvetica-Bold', leading=16)
S_BODY     = st('sBody',     fontSize=10, textColor=CINZA,       spaceBefore=4,  spaceAfter=4,  leading=15, alignment=TA_JUSTIFY)
S_BULLET   = st('sBullet',   fontSize=10, textColor=CINZA,       spaceBefore=2,  spaceAfter=2,  leading=14, leftIndent=18, bulletIndent=6)
S_CODE     = st('sCode',     fontSize=8.5,textColor=colors.HexColor('#1e293b'), fontName='Courier',
                backColor=CINZA_LIGHT, spaceBefore=6, spaceAfter=6, leading=13, leftIndent=12, rightIndent=12)
S_CAPTION  = st('sCaption',  fontSize=8,  textColor=CINZA,       alignment=TA_CENTER, spaceAfter=4, fontName='Helvetica-Oblique')
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

def code_block(lines):
    text = '<br/>'.join(lines)
    t = Table([[Paragraph(text, S_CODE)]], colWidths=[16.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), CINZA_LIGHT),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LINEAFTER', (0,0), (0,-1), 3, colors.HexColor('#6366f1')),
        ('BOX', (0,0), (-1,-1), 0.5, CINZA_MED),
    ]))
    return [t, Spacer(1, 6)]

def mk_table(headers, rows, col_widths, header_bg=AZUL):
    data = [[Paragraph(f'<b>{h}</b>', ParagraphStyle('th', fontSize=9, textColor=BRANCO,
             fontName='Helvetica-Bold', alignment=TA_CENTER)) for h in headers]]
    for i, row in enumerate(rows):
        data.append([Paragraph(str(c), ParagraphStyle('td', fontSize=9, textColor=CINZA,
                    alignment=TA_LEFT, leading=13)) for c in row])
    t = Table(data, colWidths=col_widths)
    ts = [
        ('BACKGROUND', (0,0), (-1,0), header_bg),
        ('TEXTCOLOR',  (0,0), (-1,0), BRANCO),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING',(0,0),(-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [BRANCO, CINZA_LIGHT]),
        ('GRID',       (0,0), (-1,-1), 0.4, CINZA_MED),
        ('BOX',        (0,0), (-1,-1), 1, AZUL),
    ]
    t.setStyle(TableStyle(ts))
    return [t, Spacer(1, 8)]

def bullet(text):
    return Paragraph(f'<bullet>&bull;</bullet> {text}', S_BULLET)

def step_block(num, title, lines):
    elems = []
    elems.append(Paragraph(f'<b>Passo {num} - {title}</b>', S_H2))
    elems += code_block(lines)
    return elems

def checklist_item(text, done=False):
    mark = '&#9745;' if done else '&#9744;'
    return Paragraph(f'{mark} &nbsp;{text}', S_BULLET)

# ── CAPA ──────────────────────────────────────────────────────────────────────
def build_cover():
    cover = Table(
        [[Paragraph('&#9875;', ParagraphStyle('ico', fontSize=60, textColor=BRANCO, alignment=TA_CENTER))],
         [Spacer(1, 20)],
         [Paragraph('Marina One', S_TITULO)],
         [Paragraph('Sistema SaaS de Gestao Integrada de Marina', S_SUB)],
         [Spacer(1, 30)],
         [HRFlowable(width='60%', color=colors.HexColor('#3b82f6'), thickness=2)],
         [Spacer(1, 30)],
         [Paragraph('Manual de Implantacao', ParagraphStyle('mt', fontSize=20, textColor=BRANCO,
                    alignment=TA_CENTER, fontName='Helvetica-Bold', leading=28))],
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
        ('1', 'Visao Geral do Sistema'),
        ('2', 'Arquitetura SaaS Multi-Tenant'),
        ('3', 'Requisitos e Infraestrutura'),
        ('4', 'Licencas e Dependencias'),
        ('5', 'Deploy em Producao (Railway)'),
        ('6', 'Configuracao de Dominio (Cloudflare)'),
        ('7', 'Checklist Pre-Entrega'),
        ('8', 'Custos de Operacao'),
        ('9', 'Escalabilidade'),
        ('10', 'Suporte e Contato'),
    ]
    elems = []
    elems.append(Paragraph('Sumario', S_TOC_H))
    elems.append(HRFlowable(width='100%', color=AZUL_LIGHT, thickness=1))
    elems.append(Spacer(1, 12))
    for num, title in secoes:
        row = Table([[
            Paragraph(f'<b>Secao {num}</b>', ParagraphStyle('tn', fontSize=10, textColor=AZUL_LIGHT, fontName='Helvetica-Bold')),
            Paragraph(title, S_TOC_ITEM),
        ]], colWidths=[2.8*cm, 13.7*cm])
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

    # ── S1 — VISAO GERAL ────────────────────────────────────────────────────
    E += section_header('1', 'Visao Geral do Sistema')
    E += info_box('<b>Marina One v2.0</b> e um sistema SaaS multi-tenant de gestao integrada para marinas. '
                  'Cada marina opera em schema isolado no PostgreSQL. '
                  'Deploy automatico via GitHub Actions e Railway. '
                  'Acesso por subdominio personalizado: <b>porto-belo.marinaone.com.br</b>.')

    E.append(Paragraph('<b>Stack Tecnologico</b>', S_H2))
    badges = [
        ('Node.js v20 LTS', AZUL),
        ('PostgreSQL 16', colors.HexColor('#0f766e')),
        ('postgres.js', colors.HexColor('#7c3aed')),
        ('Chart.js', colors.HexColor('#b45309')),
        ('Docker', colors.HexColor('#0369a1')),
        ('Railway', colors.HexColor('#1d4ed8')),
    ]
    rows = [badges[:3], badges[3:]]
    for row_badges in rows:
        badge_cells = []
        for label, color in row_badges:
            cell = Table([[Paragraph(label, S_BADGE)]], colWidths=[5.2*cm])
            cell.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), color),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ]))
            badge_cells.append(cell)
        badge_row = Table([badge_cells], colWidths=[5.5*cm]*3)
        badge_row.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
        E.append(badge_row)
        E.append(Spacer(1,6))

    E.append(Paragraph('<b>Modulos do Sistema</b>', S_H2))
    modulos = [
        ['Dashboard', 'Fila de Operacoes', 'Clientes', 'Embarcacoes'],
        ['Vagas', 'Contratos', 'Financeiro', 'Loja / PDV'],
        ['Manutencao', 'Analytics', 'Alertas', 'Super-Admin'],
    ]
    mod_data = []
    for row in modulos:
        mod_data.append([Paragraph(f'&#9679; {m}', ParagraphStyle('md', fontSize=9, textColor=AZUL,
                         fontName='Helvetica-Bold')) for m in row])
    mt = Table(mod_data, colWidths=[4*cm]*4)
    mt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), CINZA_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 7), ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.3, CINZA_MED),
    ]))
    E.append(mt)
    E.append(PageBreak())

    # ── S2 — ARQUITETURA MULTI-TENANT ─────────────────────────────────────
    E += section_header('2', 'Arquitetura SaaS Multi-Tenant')
    E += info_box('<b>Modelo schema-per-tenant:</b> cada marina possui seu proprio schema PostgreSQL isolado '
                  '(<b>marina_&lt;slug&gt;</b>). O schema <b>saas</b> e global e armazena a tabela de tenants '
                  'e super_admins. Nenhuma marina acessa dados de outra.')

    E.append(Paragraph('<b>Resolucao de Tenant (ordem de prioridade)</b>', S_H2))
    E += mk_table(
        ['Prioridade', 'Metodo', 'Exemplo'],
        [
            ['1 (maior)', 'Header X-Tenant-Slug', 'X-Tenant-Slug: porto-belo'],
            ['2', 'Subdominio', 'porto-belo.marinaone.com.br'],
            ['3', 'Query string', '?tenant=porto-belo'],
            ['4 (menor)', 'Env SINGLE_TENANT_SLUG', 'SINGLE_TENANT_SLUG=demo'],
        ],
        [3.5*cm, 5*cm, 8*cm]
    )

    E.append(Paragraph('<b>Schemas no PostgreSQL</b>', S_H2))
    E += mk_table(
        ['Schema', 'Conteudo'],
        [
            ['saas', 'Tabela global de tenants, super_admins'],
            ['marina_porto-belo', 'Dados exclusivos da Marina Porto Belo'],
            ['marina_santos', 'Dados exclusivos da Marina Santos'],
            ['marina_&lt;slug&gt;', 'Schema de cada marina cadastrada'],
        ],
        [5*cm, 11.5*cm]
    )

    E += info_box('<b>Super-Admin:</b> Painel exclusivo do administrador em <b>/api/superadmin/*</b> '
                  'para criar, gerenciar e monitorar todas as marinas. Acesso por JWT separado com '
                  'privilegios de nivel global.')
    E.append(PageBreak())

    # ── S3 — INFRAESTRUTURA ─────────────────────────────────────────────────
    E += section_header('3', 'Requisitos e Infraestrutura')
    E += info_box('<b>Railway</b> e a plataforma de hospedagem utilizada. Deploy automatico via GitHub. '
                  'Sem necessidade de servidor VPS ou configuracao de SO.')

    E.append(Paragraph('<b>Componentes Railway</b>', S_H2))
    E += mk_table(
        ['Componente', 'Detalhe', 'Custo'],
        [
            ['App (marina-one-app)', 'Node.js via Dockerfile', 'Plano Hobby: US$ 5/mes'],
            ['PostgreSQL', 'Gerenciado pelo Railway', 'Incluso no plano'],
            ['Volume persistente', 'postgres-volume', 'Incluso'],
            ['Dominio Railway', 'marina-one-app.up.railway.app', 'Gratuito'],
            ['Dominio customizado', '*.marinaone.com.br (Cloudflare)', 'Dominio: R$ 40/ano'],
        ],
        [5.5*cm, 6.5*cm, 4.5*cm]
    )

    E.append(Paragraph('<b>Variaveis de Ambiente Obrigatorias</b>', S_H2))
    E += code_block([
        'DATABASE_URL=${{Postgres.DATABASE_URL}}',
        'NODE_ENV=production',
        'PORT=3000',
        'DB_SSL=true',
        'JWT_SECRET=&lt;chave-secreta-forte&gt;',
        'BASE_DOMAIN=marinaone.com.br',
    ])
    E.append(PageBreak())

    # ── S4 — LICENCAS ───────────────────────────────────────────────────────
    E += section_header('4', 'Licencas e Dependencias')
    E += info_box('&#9989; <b>Custo total de licencas de software: R$ 0,00.</b> '
                  'Todo o stack open source e de uso livre, inclusive para fins comerciais.')
    E += mk_table(
        ['Componente', 'Licenca', 'Custo'],
        [
            ['Node.js v20 LTS', 'MIT', 'Gratuito'],
            ['PostgreSQL 16', 'PostgreSQL License', 'Gratuito'],
            ['postgres.js', 'MIT', 'Gratuito'],
            ['Chart.js', 'MIT', 'Gratuito'],
            ['Docker', 'Apache 2.0', 'Gratuito'],
            ['Railway', 'Comercial', 'US$ 5/mes (Hobby)'],
            ['Cloudflare', 'Comercial (Free tier)', 'Gratuito'],
            ['TOTAL LICENCAS SOFTWARE', '', 'R$ 0'],
        ],
        [6*cm, 5*cm, 5.5*cm]
    )
    E.append(PageBreak())

    # ── S5 — DEPLOY RAILWAY ─────────────────────────────────────────────────
    E += section_header('5', 'Deploy em Producao (Railway)')

    E += step_block('1', 'Pre-requisitos',
        ['- Conta Railway (railway.app)',
         '- Conta GitHub com repositorio do projeto',
         '- Railway CLI: npm install -g @railway/cli'])

    E += step_block('2', 'Criar projeto Railway',
        ['railway login',
         'railway init --name "marina-one"'])

    E += step_block('3', 'Adicionar PostgreSQL',
        ['railway add --database postgres'])

    E += step_block('4', 'Configurar variaveis de ambiente',
        ['railway variables set NODE_ENV=production PORT=3000 DB_SSL=true',
         'railway variables set JWT_SECRET=&lt;chave-secreta-forte&gt;',
         'railway variables set DATABASE_URL="${{Postgres.DATABASE_URL}}"',
         'railway variables set BASE_DOMAIN=marinaone.com.br'])

    E += step_block('5', 'Deploy inicial',
        ['railway up --service marina-one-app'])

    E += step_block('6', 'Conectar GitHub (auto-deploy)',
        ['No painel Railway: Settings > Source > MadmaxAI/marinaone > branch main',
         'No GitHub: Settings > Installed Apps > Railway App > Configure > autorizar repo'])

    E += step_block('7', 'Gerar dominio publico Railway',
        ['Via painel Railway: Settings > Networking > Generate Domain',
         '# URL gerada: marina-one-app.up.railway.app'])

    E += step_block('8', 'Atualizacoes futuras (automaticas)',
        ['publicar.bat "descricao da alteracao"',
         '# bump versao > commit > push GitHub > Railway detecta > deploy automatico'])

    E.append(PageBreak())

    # ── S6 — CLOUDFLARE ─────────────────────────────────────────────────────
    E += section_header('6', 'Configuracao de Dominio (Cloudflare)')
    E += info_box('<b>Por que Cloudflare?</b> O registro.br nao suporta wildcards DNS (* CNAME). '
                  'O Cloudflare (free tier) permite wildcard e delega o DNS do dominio. '
                  'Resultado: cada marina acessa por subdominio proprio.')

    E += step_block('1', 'Adicionar dominio no Cloudflare',
        ['Acesse cloudflare.com > Add site > marinaone.com.br'])

    E.append(Paragraph('<b>Passo 2 - Configurar DNS no Cloudflare</b>', S_H2))
    E += mk_table(
        ['Nome', 'Tipo', 'Destino', 'Proxy'],
        [
            ['*', 'CNAME', 'q8n07iv8.up.railway.app', 'DNS only (cinza)'],
            ['_acme-challenge', 'CNAME', 'q8n07iv8.authorize.railwaydns.net', 'DNS only (cinza)'],
        ],
        [3*cm, 2*cm, 7.5*cm, 4*cm]
    )
    E += info_box('<b>IMPORTANTE:</b> Ambos os registros devem estar como <b>DNS only (icone cinza)</b>, '
                  'nao como Proxied (laranja). O _acme-challenge e necessario para o Railway emitir '
                  'certificado SSL wildcard via Let\'s Encrypt.')

    E += step_block('3', 'Trocar nameservers no registro.br',
        ['- jeff.ns.cloudflare.com',
         '- kallie.ns.cloudflare.com',
         '# Aguardar propagacao: 5 min a 24h'])

    E += step_block('4', 'Verificar acesso por subdominio',
        ['https://porto-belo.marinaone.com.br  --> Marina Porto Belo',
         'https://santos.marinaone.com.br      --> Marina Santos'])

    E.append(PageBreak())

    # ── S7 — CHECKLIST ──────────────────────────────────────────────────────
    E += section_header('7', 'Checklist Pre-Entrega')
    itens = [
        'Projeto Railway criado e PostgreSQL provisionado',
        'Variaveis de ambiente configuradas corretamente',
        'Deploy inicial bem-sucedido (railway up)',
        'GitHub App Railway autorizado no repositorio',
        'Auto-deploy testado (push na branch main aciona deploy)',
        'Dominio customizado configurado no Cloudflare',
        'Nameservers atualizados no registro.br',
        'HTTPS funcionando (certificado SSL ativo)',
        'Super-admin criado e funcional',
        'Primeiro tenant (marina) provisionado e testado',
        'Credenciais padrao alteradas',
        'Sistema testado em mobile (responsividade)',
        'publicar.bat funcionando corretamente',
        'Treinamento realizado com os operadores',
    ]
    for item in itens:
        E.append(checklist_item(item))
        E.append(Spacer(1, 4))
    E.append(PageBreak())

    # ── S8 — CUSTOS ─────────────────────────────────────────────────────────
    E += section_header('8', 'Custos de Operacao')
    E += mk_table(
        ['Item', 'Descricao', 'Custo Mensal'],
        [
            ['Railway Hobby Plan', 'App + PostgreSQL gerenciado', 'US$ 5/mes (~R$ 30)'],
            ['Dominio marinaone.com.br', 'registro.br', 'R$ 40/ano (~R$ 4/mes)'],
            ['Cloudflare', 'DNS + CDN + SSL', 'Gratuito'],
            ['GitHub', 'Repositorio + CI/CD', 'Gratuito'],
            ['TOTAL', '', '~R$ 34/mes'],
        ],
        [5*cm, 7*cm, 4.5*cm]
    )
    E += info_box('<b>Nota:</b> O custo real para o cliente e a mensalidade de manutencao '
                  'contratada (R$ 1.000/mes), que <b>ja inclui</b> hospedagem Railway, '
                  'monitoramento, atualizacoes e suporte tecnico.')
    E.append(PageBreak())

    # ── S9 — ESCALABILIDADE ─────────────────────────────────────────────────
    E += section_header('9', 'Escalabilidade')
    E += info_box('<b>Atual:</b> Railway Hobby (US$5/mes) — suporta ate ~50 usuarios simultaneos '
                  'com PostgreSQL. A migracao para PostgreSQL ja foi realizada — base preparada '
                  'para escala horizontal.')
    E.append(Paragraph('<b>Quando escalar:</b>', S_H2))
    for item in [
        'Mais de 50 usuarios simultaneos',
        'Multiplas marinas grandes com relatorios pesados em tempo real',
        'Necessidade de Redis para cache de sessao',
        'Integracao com sistemas externos (ERP, contabilidade)',
    ]:
        E.append(bullet(item))
    E.append(Spacer(1,10))
    E.append(Paragraph('<b>Opcoes de upgrade:</b> Railway Pro (US$20/mes), multiplas instâncias, '
                        'Redis para cache, load balancer.', S_BODY))
    E.append(PageBreak())

    # ── S10 — SUPORTE ────────────────────────────────────────────────────────
    E += section_header('10', 'Suporte e Contato')
    planos = [
        ['Implantacao', 'R$ 3.000', 'Unico', 'Configuracao Railway, dominio, primeiro tenant, treinamento'],
        ['Manutencao Mensal', 'R$ 1.000/mes', 'Recorrente', 'Hospedagem, atualizacoes, suporte, monitoramento'],
        ['Novo Tenant', 'R$ 500', 'Por marina', 'Provisionamento, personalizacao, treinamento'],
        ['Personalizacao', 'R$ 150/hora', 'Sob demanda', 'Novos modulos, integracoes, relatorios'],
    ]
    E += mk_table(
        ['Plano', 'Valor', 'Cobranca', 'Inclui'],
        planos,
        [3.5*cm, 3*cm, 3*cm, 7*cm]
    )
    E.append(Spacer(1,10))
    contact = Table([
        [Paragraph('<b>Arthur Noli</b>', ParagraphStyle('cn', fontSize=13, textColor=AZUL,
                   fontName='Helvetica-Bold'))],
        [Paragraph('Especialista em Sistemas de Gestao para Marinas', S_BODY)],
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
    canvas.drawString(2*cm, H - 0.65*cm, 'Marina One - Manual de Implantacao')
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
        title='Manual de Implantacao - Marina One',
        author='Arthur Noli',
        subject='Sistema SaaS de Gestao Integrada de Marina',
    )
    story = []
    story += build_cover()
    story += build_toc()
    story += build_body()
    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    print(f'PDF gerado: {OUT}')

if __name__ == '__main__':
    main()
