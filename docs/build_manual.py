# -*- coding: utf-8 -*-
"""
Marina One v2.0 — Manual de Implantação e Arquitetura
Gerador de PDF com ReportLab
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, PageBreak,
    Table, TableStyle, NextPageTemplate, KeepTogether
)

OUT = r"C:\Users\Arthur Noli\marina-one\docs\Manual de Implantação — Marina One.pdf"

# ── Paleta de cores ──────────────────────────────────────────────────
PRIMARY  = colors.HexColor("#1e3a5f")
ACCENT   = colors.HexColor("#2c5282")
ACCENT2  = colors.HexColor("#1a56db")
LIGHT    = colors.HexColor("#f1f5f9")
GREY     = colors.HexColor("#64748b")
BORDER   = colors.HexColor("#cbd5e1")
DARK     = colors.HexColor("#0f172a")
GREEN    = colors.HexColor("#166534")
GREEN_L  = colors.HexColor("#dcfce7")
GREEN_B  = colors.HexColor("#16a34a")
WARN     = colors.HexColor("#92400e")
WARN_L   = colors.HexColor("#fef3c7")
WARN_B   = colors.HexColor("#d97706")
PURPLE   = colors.HexColor("#4c1d95")
PURPLE_L = colors.HexColor("#ede9fe")
PURPLE_B = colors.HexColor("#7c3aed")
BLUE_L   = colors.HexColor("#eff6ff")
BLUE_B   = colors.HexColor("#3b82f6")
ROW_ALT  = colors.HexColor("#f8fafc")

styles = getSampleStyleSheet()

def S(name, **kw):
    base = kw.pop("parent", styles["Normal"])
    return ParagraphStyle(name, parent=base, **kw)

st_title      = S("TitleBig",   fontName="Helvetica-Bold", fontSize=34, leading=40, textColor=colors.white, alignment=TA_CENTER)
st_subtitle   = S("SubTitle",   fontName="Helvetica",      fontSize=15, leading=21, textColor=colors.white, alignment=TA_CENTER)
st_version    = S("Version",    fontName="Helvetica-Bold", fontSize=13, leading=18, textColor=colors.HexColor("#93c5fd"), alignment=TA_CENTER)
st_coverSmall = S("CoverSmall", fontName="Helvetica",      fontSize=11, leading=16, textColor=colors.whitesmoke, alignment=TA_CENTER)
st_h1   = S("H1",   fontName="Helvetica-Bold", fontSize=17, leading=23, textColor=PRIMARY, spaceBefore=6, spaceAfter=10)
st_h2   = S("H2",   fontName="Helvetica-Bold", fontSize=12.5, leading=17, textColor=ACCENT, spaceBefore=10, spaceAfter=5)
st_h3   = S("H3",   fontName="Helvetica-Bold", fontSize=11, leading=15, textColor=DARK, spaceBefore=6, spaceAfter=4)
st_body = S("Body", fontName="Helvetica", fontSize=10.5, leading=15, textColor=DARK, alignment=TA_JUSTIFY, spaceAfter=5)
st_body_l = S("BodyL", fontName="Helvetica", fontSize=10.5, leading=15, textColor=DARK, spaceAfter=5)
st_bullet = S("Bullet", parent=st_body_l, leftIndent=14, bulletIndent=2, spaceAfter=3)
st_code   = S("Code", fontName="Courier", fontSize=8, leading=11.5, textColor=colors.HexColor("#e2e8f0"),
              backColor=colors.HexColor("#1e293b"), leftIndent=6, rightIndent=6,
              spaceBefore=4, spaceAfter=8, borderPadding=(8, 8, 8, 8))
st_code_sm = S("CodeSm", fontName="Courier", fontSize=7.5, leading=11, textColor=colors.HexColor("#e2e8f0"),
               backColor=colors.HexColor("#1e293b"), leftIndent=6, rightIndent=6,
               spaceBefore=4, spaceAfter=8, borderPadding=(6, 6, 6, 6))
st_note    = S("Note",   parent=st_body, textColor=GREY, fontSize=9.5, leading=13)
st_toc_item= S("TOCItem", fontName="Helvetica",      fontSize=11, leading=18, textColor=DARK)
st_toc_num = S("TOCNum",  fontName="Helvetica-Bold", fontSize=11, leading=18, textColor=PRIMARY)
st_mono    = S("Mono",    fontName="Courier", fontSize=9, leading=13, textColor=DARK)
st_tag     = S("Tag",     fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=colors.white, alignment=TA_CENTER)

# ── Page templates ───────────────────────────────────────────────────
def cover_page(canv, doc):
    canv.saveState()
    w, h = A4
    # Fundo gradiente simulado (duas faixas)
    canv.setFillColor(PRIMARY); canv.rect(0, 0, w, h, fill=1, stroke=0)
    canv.setFillColor(colors.HexColor("#0d2137")); canv.rect(0, 0, w, h*0.38, fill=1, stroke=0)
    # Linha decorativa
    canv.setFillColor(ACCENT2); canv.rect(0, h*0.58 - 1, w, 5, fill=1, stroke=0)
    canv.setFillColor(colors.white); canv.rect(0, h*0.58 - 1, w*0.22, 5, fill=1, stroke=0)
    # Badge v2.0 no canto inferior direito
    canv.setFillColor(ACCENT2)
    canv.roundRect(w - 3.5*cm, 1.5*cm, 2.8*cm, 1.1*cm, 6, fill=1, stroke=0)
    canv.setFillColor(colors.white); canv.setFont("Helvetica-Bold", 11)
    canv.drawCentredString(w - 2.1*cm, 2.0*cm, "v2.0 SaaS")
    canv.restoreState()

def content_page(canv, doc):
    canv.saveState()
    w, h = A4
    canv.setFillColor(PRIMARY); canv.rect(0, h - 1.4*cm, w, 1.4*cm, fill=1, stroke=0)
    canv.setFillColor(colors.white)
    canv.setFont("Helvetica-Bold", 10); canv.drawString(2*cm, h - 0.9*cm, "Marina One")
    canv.setFont("Helvetica", 9);       canv.drawRightString(w - 2*cm, h - 0.9*cm, "Manual de Implantação e Arquitetura · v2.0")
    canv.setStrokeColor(BORDER); canv.setLineWidth(0.5)
    canv.line(2*cm, 1.6*cm, w - 2*cm, 1.6*cm)
    canv.setFillColor(GREY); canv.setFont("Helvetica", 9)
    canv.drawString(2*cm, 1.1*cm, "© 2025 Marina One — Sistema SaaS Multi-Tenant")
    canv.drawRightString(w - 2*cm, 1.1*cm, f"Página {doc.page - 1}")
    canv.restoreState()

doc = BaseDocTemplate(
    OUT, pagesize=A4,
    leftMargin=2*cm, rightMargin=2*cm, topMargin=2.2*cm, bottomMargin=2*cm,
    title="Manual de Implantação e Arquitetura — Marina One v2.0",
    author="Arthur Noli"
)
frame_cover   = Frame(0, 0, A4[0], A4[1], leftPadding=2*cm, rightPadding=2*cm,
                      topPadding=2*cm, bottomPadding=2*cm, id="cover")
frame_content = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="content")
doc.addPageTemplates([
    PageTemplate(id="Cover",   frames=[frame_cover],   onPage=cover_page),
    PageTemplate(id="Content", frames=[frame_content], onPage=content_page),
])

story = []

# ════════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════════
def section(num, title):
    banner = Table(
        [[Paragraph(f"<font color='white'><b>{num}</b></font>", st_h1),
          Paragraph(f"<font color='white'><b>{title}</b></font>", st_h1)]],
        colWidths=[1.3*cm, 15*cm])
    banner.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), PRIMARY),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(banner)
    story.append(Spacer(1, 0.35*cm))

def code_block(text, small=False):
    st = st_code_sm if small else st_code
    text = text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\n","<br/>").replace(" ","&nbsp;")
    story.append(Paragraph(f"<font face='Courier' color='#e2e8f0'>{text}</font>", st))

def bullet(txt, indent=14):
    story.append(Paragraph(f"• &nbsp;{txt}", S(f"BulletD{indent}", parent=st_body_l, leftIndent=indent, spaceAfter=3)))

def info_box(text, bg=None, border=None):
    bg     = bg     or BLUE_L
    border = border or BLUE_B
    t = Table([[Paragraph(text, st_body)]], colWidths=[16.3*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), bg),
        ("LEFTPADDING",   (0,0), (-1,-1), 14),
        ("RIGHTPADDING",  (0,0), (-1,-1), 14),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LINEBEFORE",    (0,0), (0,-1),  3, border),
        ("BOX",           (0,0), (-1,-1), 0.5, border),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.25*cm))

def kv_table(rows, col_w=None):
    col_w = col_w or [4.5*cm, 12*cm]
    t = Table(rows, colWidths=col_w)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (0,-1), LIGHT),
        ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
        ("TEXTCOLOR",     (0,0), (0,-1), PRIMARY),
        ("FONTSIZE",      (0,0), (-1,-1), 10),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.2*cm))

def data_table(header_row, data_rows, col_widths, alt=True):
    all_rows = [header_row] + data_rows
    t = Table(all_rows, colWidths=col_widths)
    style = [
        ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
        ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 10),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0), (-1,-1), 9),
        ("RIGHTPADDING",  (0,0), (-1,-1), 9),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
    ]
    if alt:
        for i in range(1, len(all_rows)):
            bg = ROW_ALT if i % 2 == 0 else colors.white
            style.append(("BACKGROUND", (0,i), (-1,i), bg))
    t.setStyle(TableStyle(style))
    story.append(t)
    story.append(Spacer(1, 0.25*cm))

def tag(text, bg):
    t = Table([[Paragraph(f"<b>{text}</b>", st_tag)]], colWidths=[2.4*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), bg),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
    ]))
    return t

# ════════════════════════════════════════════════════════════════════
#  CAPA
# ════════════════════════════════════════════════════════════════════
story.append(Spacer(1, 4.5*cm))
story.append(Paragraph("Marina One", st_title))
story.append(Spacer(1, 0.35*cm))
story.append(Paragraph("Sistema SaaS de Gestão Integrada de Marina", st_subtitle))
story.append(Spacer(1, 0.4*cm))
story.append(Paragraph("Multi-Tenant · PostgreSQL · Node.js 20", st_version))
story.append(Spacer(1, 4*cm))
story.append(Paragraph("MANUAL DE IMPLANTAÇÃO E ARQUITETURA", st_subtitle))
story.append(Spacer(1, 0.4*cm))
story.append(Paragraph("Versão 2.0 — 2025", st_coverSmall))
story.append(NextPageTemplate("Content"))
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SUMÁRIO
# ════════════════════════════════════════════════════════════════════
story.append(Paragraph("Sumário", st_h1))
story.append(Spacer(1, 0.2*cm))
toc_items = [
    ("1",  "Visão Geral do Sistema v2.0",           3),
    ("2",  "Arquitetura Multi-Tenant",               4),
    ("3",  "Requisitos de Infraestrutura",           6),
    ("4",  "Licenças e Dependências",                7),
    ("5",  "Implantação Passo a Passo",              8),
    ("6",  "Gerenciamento de Tenants (Super-Admin)", 12),
    ("7",  "Desenvolvimento Local com Docker",       13),
    ("8",  "Checklist Pré-Entrega",                 14),
    ("9",  "Custos de Operação",                    15),
    ("10", "Processo de Atualização",               16),
    ("11", "Escalabilidade e Roadmap",              19),
    ("12", "Suporte e Contato",                     20),
]
toc_data = [[
    Paragraph(f"<b>{n}</b>", st_toc_num),
    Paragraph(t, st_toc_item),
    Paragraph(f"<font color='#64748b'>pág. {p}</font>", st_toc_item),
] for n, t, p in toc_items]
toc_tbl = Table(toc_data, colWidths=[1.4*cm, 12.5*cm, 2.5*cm])
toc_tbl.setStyle(TableStyle([
    ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ("LINEBELOW",     (0,0), (-1,-1), 0.4, BORDER),
    ("TOPPADDING",    (0,0), (-1,-1), 6),
    ("BOTTOMPADDING", (0,0), (-1,-1), 6),
]))
story.append(toc_tbl)
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 1 — VISÃO GERAL v2.0
# ════════════════════════════════════════════════════════════════════
section("1", "Visão Geral do Sistema v2.0")
story.append(Paragraph(
    "O <b>Marina One v2.0</b> é um sistema <b>SaaS multi-tenant</b> de gestão integrada "
    "para marinas. A versão 2.0 migrou completamente a arquitetura para <b>PostgreSQL</b> "
    "com isolamento por schema (schema-per-tenant), permitindo atender múltiplas marinas "
    "em uma única instância do sistema com segurança e escalabilidade.", st_body))

story.append(Paragraph("Stack tecnológico v2.0", st_h2))
stack_data = [
    ["Node.js v20 LTS", "postgres.js 3.x", "PostgreSQL 16", "Chart.js · HTML5 / JS"],
]
st_tbl = Table(stack_data, colWidths=[4.0*cm]*4)
st_tbl.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (-1,-1), LIGHT),
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("ALIGN",         (0,0), (-1,-1), "CENTER"),
    ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
    ("FONTSIZE",      (0,0), (-1,-1), 9.5),
    ("TEXTCOLOR",     (0,0), (-1,-1), PRIMARY),
    ("TOPPADDING",    (0,0), (-1,-1), 11),
    ("BOTTOMPADDING", (0,0), (-1,-1), 11),
]))
story.append(st_tbl)
story.append(Spacer(1, 0.35*cm))

story.append(Paragraph("Módulos do sistema", st_h2))
modulos = ["Dashboard","Fila de Operações","Clientes","Embarcações","Vagas",
           "Contratos","Financeiro","Loja / PDV","Manutenção","Analytics","Alertas","Configurações"]
rows = [modulos[i:i+3] for i in range(0, len(modulos), 3)]
mod_tbl = Table(rows, colWidths=[5.4*cm]*3)
mod_tbl.setStyle(TableStyle([
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("FONTSIZE",      (0,0), (-1,-1), 10),
    ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ("TOPPADDING",    (0,0), (-1,-1), 8),
    ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ("ROWBACKGROUNDS",(0,0), (-1,-1), [LIGHT, colors.white]),
]))
story.append(mod_tbl)
story.append(Spacer(1, 0.4*cm))

story.append(Paragraph("Principais mudanças da v1.x para v2.0", st_h2))
changes = [
    ["Aspecto",        "v1.x (SQLite)",                     "v2.0 (PostgreSQL SaaS)"],
    ["Banco de dados", "SQLite — arquivo local marina.db",  "PostgreSQL — schema por tenant"],
    ["Multi-tenant",   "Instância por cliente",             "Compartilhada — schema isolado"],
    ["Atualização",    "Servidor por servidor",             "Um deploy atualiza todos"],
    ["Escalabilidade", "~10 usuários simultâneos",          "Centenas de tenants"],
    ["Deploy",         "VPS ou servidor local",             "Railway, Render ou VPS + Docker"],
    ["Super-admin",    "Não existia",                       "Painel /api/superadmin/*"],
]
data_table(changes[0], changes[1:], [3.8*cm, 5.5*cm, 7.1*cm])
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 2 — ARQUITETURA MULTI-TENANT
# ════════════════════════════════════════════════════════════════════
section("2", "Arquitetura Multi-Tenant")

story.append(Paragraph("Modelo: Schema-per-Tenant no PostgreSQL", st_h2))
story.append(Paragraph(
    "Cada marina possui um <b>schema PostgreSQL exclusivo</b> "
    "(<font face='Courier'>marina_&lt;slug&gt;</font>). "
    "As tabelas de uma marina jamais são acessíveis por outra — o isolamento é "
    "garantido pelo banco de dados. Um schema global "
    "(<font face='Courier'>saas</font>) armazena o catálogo de tenants e os "
    "super-admins.", st_body))

# Diagrama de arquitetura (texto estruturado)
arch_text = (
    "Banco de Dados PostgreSQL<br/>"
    "<br/>"
    "  saas.tenants         — registro de todas as marinas<br/>"
    "  saas.super_admins    — acesso de Arthur ao painel SaaS<br/>"
    "<br/>"
    "  marina_porto-belo.*  — schema exclusivo da Marina Porto Belo<br/>"
    "  marina_angra.*       — schema exclusivo da Marina Angra<br/>"
    "  marina_buzios.*      — schema exclusivo da Marina Búzios<br/>"
    "  ..."
)
arch_box = Table([[Paragraph(arch_text, st_mono)]], colWidths=[16.3*cm])
arch_box.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#1e293b")),
    ("TEXTCOLOR",     (0,0), (-1,-1), colors.HexColor("#94a3b8")),
    ("LEFTPADDING",   (0,0), (-1,-1), 16),
    ("RIGHTPADDING",  (0,0), (-1,-1), 16),
    ("TOPPADDING",    (0,0), (-1,-1), 12),
    ("BOTTOMPADDING", (0,0), (-1,-1), 12),
    ("BOX",           (0,0), (-1,-1), 1, colors.HexColor("#334155")),
]))
story.append(arch_box)
story.append(Spacer(1, 0.35*cm))

story.append(Paragraph("Fluxo de Resolução de Tenant por Requisição", st_h2))
flow = [
    ["1", "Requisição HTTP chega", "GET /api/clients — com header X-Tenant-Slug: porto-belo"],
    ["2", "Middleware de tenant",  "Valida slug contra saas.tenants, verifica se está ativo"],
    ["3", "Middleware de auth",    "Valida JWT — verifica tenant_slug do token vs requisição"],
    ["4", "Pool de conexão",       "getTenantPool('porto-belo') — search_path = marina_porto-belo"],
    ["5", "Route handler",         "SELECT * FROM clients — busca apenas no schema porto-belo"],
    ["6", "Resposta",              "Dados isolados retornados ao cliente"],
]
t = Table(flow, colWidths=[0.7*cm, 3.8*cm, 12*cm])
t.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (0,-1), PRIMARY),
    ("TEXTCOLOR",     (0,0), (0,-1), colors.white),
    ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
    ("ALIGN",         (0,0), (0,-1), "CENTER"),
    ("BACKGROUND",    (1,0), (1,-1), LIGHT),
    ("FONTNAME",      (1,0), (1,-1), "Helvetica-Bold"),
    ("TEXTCOLOR",     (1,0), (1,-1), ACCENT),
    ("FONTSIZE",      (0,0), (-1,-1), 9.5),
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ("TOPPADDING",    (0,0), (-1,-1), 7),
    ("BOTTOMPADDING", (0,0), (-1,-1), 7),
]))
story.append(t)
story.append(Spacer(1, 0.35*cm))

story.append(Paragraph("JWT Vinculado ao Tenant", st_h2))
story.append(Paragraph(
    "Cada token JWT inclui <font face='Courier'>tenant_slug</font>. O middleware de "
    "autenticação rejeita tokens de tenants diferentes, impedindo que um usuário "
    "da Marina Porto Belo acesse dados da Marina Angra mesmo com token válido.", st_body))
code_block(
"""{
  "user_id":     42,
  "email":       "gerente@portobelo.com",
  "role":        "admin",
  "tenant_id":   3,
  "tenant_slug": "porto-belo",
  "exp":         1750000000
}""", small=True)

story.append(Paragraph("Resolução de Tenant — Estratégias (em prioridade)", st_h2))
kv_table([
    ["1° Prioridade", "Header X-Tenant-Slug (injetado pelo NGINX — produção)"],
    ["2° Prioridade", "Variável SINGLE_TENANT_SLUG no ambiente (modo single-tenant)"],
    ["3° Prioridade", "Subdomínio do Host: porto-belo.marinaone.com.br"],
    ["4° Prioridade", "Query string ?tenant=porto-belo (apenas em desenvolvimento)"],
], col_w=[3.5*cm, 13*cm])
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 3 — INFRAESTRUTURA
# ════════════════════════════════════════════════════════════════════
section("3", "Requisitos de Infraestrutura")

story.append(Paragraph("Opção A — SaaS Gerenciado (Recomendado)", st_h2))
info_box(
    "<b>Melhor custo-benefício para SaaS</b>: zero ops, escalabilidade automática, "
    "deploy em segundos via git push.",
    bg=GREEN_L, border=GREEN_B)
kv_table([
    ["Banco de dados", "Neon.tech (PostgreSQL serverless) — plano gratuito até 0,5 GB, ~R$ 30/mês para produção"],
    ["Aplicação",      "Railway.app ou Render.com — plano Hobby R$ 25–60/mês · zero configuração"],
    ["Domínio",        "R$ 40–60/ano · wildcard *.marinaone.com.br via Cloudflare (SSL gratuito)"],
    ["Total estimado", "R$ 55–100/mês para múltiplas marinas — custo fixo independente do número de tenants"],
], col_w=[3.8*cm, 12.7*cm])

story.append(Paragraph("Opção B — VPS com PostgreSQL (Controle Total)", st_h2))
kv_table([
    ["Servidor",    "2 vCPU, 4GB RAM, 40GB SSD — Hostinger VPS, DigitalOcean, Vultr"],
    ["Custo mensal","R$ 80–150/mês"],
    ["PostgreSQL",  "Instalado no próprio servidor ou serviço gerenciado (Supabase, Neon)"],
    ["SSL",         "Certbot wildcard via Cloudflare DNS-01 + NGINX"],
    ["Backup",      "pg_dump diário via cron · retenção 30 dias"],
])

story.append(Paragraph("Opção C — Servidor Local (Single-Tenant, sem escala)", st_h2))
kv_table([
    ["Hardware",    "Mini PC (Intel NUC) 8GB RAM — R$ 800–1.500 (custo único)"],
    ["PostgreSQL",  "Instalado localmente via Docker: docker compose up -d"],
    ["Acesso",      "Tailscale ou Cloudflare Tunnel (gratuito)"],
    ["Modo",        "SINGLE_TENANT_SLUG no .env — sem subdomínios, uma marina por instância"],
])
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 4 — LICENÇAS
# ════════════════════════════════════════════════════════════════════
section("4", "Licenças e Dependências")
lic_data = [
    ["Componente",           "Versão",   "Licença", "Custo"],
    ["Node.js",              "v20 LTS",  "MIT",     "Gratuito"],
    ["postgres.js",          "3.x",      "MIT",     "Gratuito"],
    ["PostgreSQL",           "16",       "PostgreSQL (BSD)", "Gratuito"],
    ["Chart.js (CDN)",       "4.x",      "MIT",     "Gratuito"],
    ["Ubuntu / Alpine",      "22.04 LTS","Free",    "Gratuito"],
    ["Docker",               "24+",      "Apache 2","Gratuito"],
    ["TOTAL",                "—",        "—",       "R$ 0"],
]
t = Table(lic_data, colWidths=[5.5*cm, 2.5*cm, 4*cm, 4.5*cm])
t.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
    ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
    ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
    ("FONTSIZE",      (0,0), (-1,-1), 10.5),
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("ROWBACKGROUNDS",(0,1), (-1,-2), [colors.white, LIGHT]),
    ("BACKGROUND",    (0,-1),(-1,-1), colors.HexColor("#e6efc8")),
    ("FONTNAME",      (0,-1),(-1,-1), "Helvetica-Bold"),
    ("TEXTCOLOR",     (0,-1),(-1,-1), PRIMARY),
    ("ALIGN",         (2,0), (-1,-1), "CENTER"),
    ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ("TOPPADDING",    (0,0), (-1,-1), 8),
    ("BOTTOMPADDING", (0,0), (-1,-1), 8),
]))
story.append(t)
story.append(Spacer(1, 0.4*cm))
info_box(
    "<b>Stack 100% open source.</b> Nenhuma dependência paga — "
    "o custo de operação é exclusivamente de infraestrutura (hospedagem e domínio).")
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 5 — IMPLANTAÇÃO
# ════════════════════════════════════════════════════════════════════
section("5", "Implantação Passo a Passo")

story.append(Paragraph("5A — Deploy SaaS Gerenciado (Railway + Neon) — Recomendado", st_h2))
story.append(Paragraph(
    "A forma mais rápida de colocar o sistema no ar para múltiplas marinas. "
    "O Railway detecta o <font face='Courier'>Dockerfile</font> e sobe automaticamente.", st_body))

steps_saas = [
    ["1", "Neon.tech",    "Criar banco PostgreSQL gratuito · copiar a DATABASE_URL"],
    ["2", "Cloudflare",   "Registrar domínio · configurar wildcard *.marinaone.com.br"],
    ["3", "GitHub",       "Criar repositório privado · push do código"],
    ["4", "Railway.app",  "New Project → Deploy from GitHub · variáveis de ambiente abaixo"],
    ["5", "Health check", "Acessar /api/version e confirmar resposta com version: 2.0.0"],
    ["6", "1ª Marina",    "POST /api/superadmin/tenants para criar o primeiro tenant"],
]
t = Table(steps_saas, colWidths=[0.6*cm, 3*cm, 12.8*cm])
t.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (0,-1), PRIMARY),
    ("TEXTCOLOR",     (0,0), (0,-1), colors.white),
    ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
    ("ALIGN",         (0,0), (0,-1), "CENTER"),
    ("BACKGROUND",    (1,0), (1,-1), LIGHT),
    ("FONTNAME",      (1,0), (1,-1), "Helvetica-Bold"),
    ("TEXTCOLOR",     (1,0), (1,-1), ACCENT),
    ("FONTSIZE",      (0,0), (-1,-1), 9.5),
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ("TOPPADDING",    (0,0), (-1,-1), 7),
    ("BOTTOMPADDING", (0,0), (-1,-1), 7),
]))
story.append(t)
story.append(Spacer(1, 0.3*cm))
story.append(Paragraph("Variáveis de ambiente obrigatórias no Railway:", st_h3))
code_block(
"""DATABASE_URL=postgres://usuario:senha@ep-xxx.neon.tech/marinaone?sslmode=require
DB_SSL=true
JWT_SECRET=string_aleatoria_minimo_32_chars
BASE_DOMAIN=marinaone.com.br
SUPER_ADMIN_EMAIL=arthur@marinaone.com.br
SUPER_ADMIN_PASSWORD=senha_super_admin_forte
NODE_ENV=production""", small=True)
story.append(PageBreak())

story.append(Paragraph("5B — Deploy em VPS com PostgreSQL", st_h2))
story.append(Paragraph("Passo 1 — Preparar servidor Ubuntu 22.04", st_h3))
code_block(
"""sudo apt update && sudo apt upgrade -y
# Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs git nginx certbot python3-certbot-nginx
node -v   # Verificar: v20.x.x

# PostgreSQL 16
sudo apt install -y postgresql-16
sudo -u postgres psql -c "CREATE USER marinaone WITH PASSWORD 'senha_forte';"
sudo -u postgres psql -c "CREATE DATABASE marinaone OWNER marinaone;" """, small=True)

story.append(Paragraph("Passo 2 — Clonar e configurar a aplicação", st_h3))
code_block(
"""git clone https://github.com/seuusuario/marina-one.git
cd marina-one
npm install --omit=dev

# Criar .env
cp .env.example .env
nano .env   # Preencher DATABASE_URL, JWT_SECRET, etc.""", small=True)

story.append(Paragraph("Passo 3 — PM2 (processo sempre online)", st_h3))
code_block(
"""sudo npm install -g pm2
pm2 start server.js --name marina-one
pm2 startup && pm2 save
# Aguardar startup — o sistema cria os schemas automaticamente""", small=True)

story.append(Paragraph("Passo 4 — NGINX com wildcard + HTTPS", st_h3))
story.append(Paragraph(
    "Copie o arquivo <font face='Courier'>nginx/nginx.conf</font> do projeto para "
    "<font face='Courier'>/etc/nginx/sites-available/marina-one</font> e habilite-o:", st_body_l))
code_block(
"""# Habilitar site
sudo ln -s /etc/nginx/sites-available/marina-one /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Wildcard SSL via Cloudflare DNS-01
sudo certbot certonly --dns-cloudflare \\
  --dns-cloudflare-credentials ~/.cloudflare.ini \\
  -d marinaone.com.br -d '*.marinaone.com.br'""", small=True)

story.append(Paragraph("Passo 5 — Backup automático do banco", st_h3))
code_block(
"""# /etc/cron.d/marina-backup
0 2 * * * postgres pg_dump marinaone \\
    | gzip > /backups/marina-$(date +%Y-%m-%d).sql.gz
0 3 * * * root find /backups -name 'marina-*.gz' -mtime +30 -delete""", small=True)
story.append(PageBreak())

story.append(Paragraph("5C — Modo Single-Tenant (uma marina por instância)", st_h2))
story.append(Paragraph(
    "Para implantar o sistema para uma única marina sem subdomínios, defina a variável "
    "<font face='Courier'>SINGLE_TENANT_SLUG</font> no ambiente. O sistema cria e migra "
    "o schema automaticamente no primeiro start:", st_body))
code_block(
"""# .env — modo single-tenant
DATABASE_URL=postgres://marinaone:senha@localhost:5432/marinaone
JWT_SECRET=sua_chave_secreta_aqui
SINGLE_TENANT_SLUG=porto-belo
SINGLE_TENANT_NAME=Marina Porto Belo
ADMIN_EMAIL=admin@portobelo.com
ADMIN_PASSWORD=senha_inicial_admin""")
info_box(
    "<b>Vantagem do modo single-tenant:</b> funciona exatamente como a v1.x do ponto de vista "
    "do usuário final — mesma URL, sem subdomínio. O frontend <b>não precisa de nenhuma "
    "alteração</b>. Ideal para a primeira comercialização.")
story.append(Paragraph("Passo 6 — Personalização do tenant", st_h2))
bullet("Trocar credenciais do admin em Usuários → admin@marina.com / marina123")
bullet("Personalizar nome da marina em Configurações → Marina")
bullet("Criar usuários para a equipe (Operador, Loja/PDV)")
bullet("Configurar horários e checklists de operação em Configurações")
bullet("Cadastrar vagas secas e molhadas na tela de Vagas")
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 6 — SUPER-ADMIN / GERENCIAMENTO DE TENANTS
# ════════════════════════════════════════════════════════════════════
section("6", "Gerenciamento de Tenants — Painel Super-Admin")

story.append(Paragraph(
    "O painel super-admin é exclusivo do Arthur Noli (SaaS Owner). Permite criar novas "
    "marinas, consultar estatísticas e ativar/desativar tenants — tudo via API REST "
    "autenticada separadamente do sistema das marinas.", st_body))

story.append(Paragraph("Autenticação do Super-Admin", st_h2))
code_block(
"""POST /api/superadmin/auth/login
{
  "email": "arthur@marinaone.com.br",
  "password": "SaaS@Marina2025!"
}

# Resposta → { "token": "eyJ...", "admin": { "name": "Arthur Noli" } }""", small=True)

story.append(Paragraph("Endpoints disponíveis", st_h2))
ep_data = [
    ["Método", "Endpoint",                              "Função"],
    ["POST",   "/api/superadmin/auth/login",            "Autenticação do super-admin"],
    ["GET",    "/api/superadmin/tenants",               "Listar todas as marinas"],
    ["POST",   "/api/superadmin/tenants",               "Criar e provisionar nova marina"],
    ["PUT",    "/api/superadmin/tenants/:slug",         "Atualizar nome, plano ou status"],
    ["GET",    "/api/superadmin/tenants/:slug/stats",   "KPIs da marina (clientes, receita...)"],
]
data_table(ep_data[0], ep_data[1:], [1.8*cm, 7*cm, 7.7*cm])

story.append(Paragraph("Criar uma nova marina (provisionamento completo)", st_h2))
code_block(
"""POST /api/superadmin/tenants
Authorization: Bearer <super-admin-token>
{
  "slug":          "porto-belo",
  "name":          "Marina Porto Belo",
  "plan":          "professional",
  "adminEmail":    "admin@portobelo.com",
  "adminPassword": "senha_segura_123",
  "adminName":     "Gerente Porto Belo"
}
# O sistema automaticamente:
# 1. Registra em saas.tenants
# 2. Cria schema marina_porto-belo
# 3. Executa todas as migrações SQL
# 4. Faz seed do admin, operador e permissões
# Marina está pronta em segundos.""", small=True)
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 7 — DOCKER / DESENVOLVIMENTO LOCAL
# ════════════════════════════════════════════════════════════════════
section("7", "Desenvolvimento Local com Docker")

story.append(Paragraph(
    "O projeto inclui um <font face='Courier'>docker-compose.yml</font> completo para "
    "subir o ambiente de desenvolvimento em um único comando, com PostgreSQL 16.", st_body))

code_block(
"""# Subir tudo (PostgreSQL + App)
docker compose up -d

# Verificar se o app está rodando
curl http://localhost:3000/api/version

# Ver logs em tempo real
docker compose logs -f app

# Parar o ambiente
docker compose down""")

story.append(Paragraph(
    "O Docker Compose configura automaticamente a variável "
    "<font face='Courier'>SINGLE_TENANT_SLUG=demo</font>, então o sistema sobe "
    "com a marina <b>demo</b> pronta para uso imediato.", st_body))

story.append(Paragraph("Sem Docker — Node.js + PostgreSQL local", st_h2))
code_block(
"""# 1. PostgreSQL local instalado e rodando
# 2. Criar .env com DATABASE_URL
cp .env.example .env   # editar DATABASE_URL

# 3. Instalar dependências
npm install

# 4. Iniciar (schemas criados automaticamente no boot)
npm start""")
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 8 — CHECKLIST PRÉ-ENTREGA
# ════════════════════════════════════════════════════════════════════
section("8", "Checklist Pré-Entrega")
check_infra = [
    "DATABASE_URL configurada e banco PostgreSQL acessível",
    "JWT_SECRET com mínimo 32 caracteres aleatórios (não use o padrão do .env.example)",
    "HTTPS funcionando — cadeado verde em todos os acessos",
    "Wildcard SSL *.marinaone.com.br configurado (ou domínio do cliente)",
    "Endpoint /api/version respondendo com version: 2.0.0",
    "Firewall configurado (apenas portas 80, 443 e 22 abertas)",
    "Backup automático do banco testado e verificado",
    "PM2 iniciando no boot: reiniciar servidor e confirmar",
]
check_config = [
    "Credenciais do super-admin trocadas (não usar senha padrão em produção)",
    "Tenant da marina criado via POST /api/superadmin/tenants",
    "Admin da marina com senha trocada (padrão: marina123)",
    "Nome e dados da marina configurados em Configurações",
    "Usuários da equipe criados (Operador, Loja/PDV)",
    "Vagas secas e molhadas cadastradas",
    "PIX configurado em Loja → Configurações PIX",
    "Horários de operação configurados",
]
check_qa = [
    "Testar login com todos os perfis (admin, operador, loja, cliente)",
    "Testar fluxo completo: criar cliente → embarcação → contrato → cobrança",
    "Testar fila de operações (descida, subida, atracação)",
    "Testar PDV — criar pedido, confirmar pagamento, delivery",
    "Verificar responsividade em celular",
    "Demonstração completa com o cliente",
]

for titulo, items in [("Infraestrutura e Servidor", check_infra),
                      ("Configuração do Tenant",    check_config),
                      ("Testes e Qualidade",         check_qa)]:
    story.append(Paragraph(titulo, st_h2))
    check_data = [["☐", Paragraph(item, st_body)] for item in items]
    t = Table(check_data, colWidths=[1.2*cm, 15.3*cm])
    t.setStyle(TableStyle([
        ("FONTSIZE",      (0,0), (0,-1), 15),
        ("TEXTCOLOR",     (0,0), (0,-1), PRIMARY),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("LINEBELOW",     (0,0), (-1,-1), 0.4, BORDER),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.3*cm))
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 9 — CUSTOS
# ════════════════════════════════════════════════════════════════════
section("9", "Custos de Operação")

story.append(Paragraph("Modelo SaaS — Custo Fixo para N Marinas", st_h2))
info_box(
    "Com a arquitetura multi-tenant, o custo de infraestrutura é <b>fixo</b> "
    "independente do número de marinas. Adicionar a 10ª marina tem o mesmo custo "
    "da 1ª — apenas armazenamento aumenta marginalmente.")

cost_saas = [
    ["Item",                        "Serviço",              "Custo"],
    ["Banco de dados PostgreSQL",   "Neon.tech Pro",        "~R$ 30/mês"],
    ["Aplicação (hospedagem)",      "Railway / Render",     "R$ 25–60/mês"],
    ["Domínio wildcard",            "Cloudflare + registro","~R$ 5/mês (pró-rata)"],
    ["SSL wildcard",                "Cloudflare (gratuito)","R$ 0"],
    ["Licenças de software",        "—",                    "R$ 0"],
    ["TOTAL (SaaS gerenciado)",     "—",                    "R$ 60–95/mês"],
]
t = Table(cost_saas, colWidths=[5.5*cm, 5*cm, 6*cm])
t.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
    ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
    ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
    ("FONTSIZE",      (0,0), (-1,-1), 10.5),
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("ROWBACKGROUNDS",(0,1), (-1,-2), [colors.white, LIGHT]),
    ("BACKGROUND",    (0,-1),(-1,-1), colors.HexColor("#e6efc8")),
    ("FONTNAME",      (0,-1),(-1,-1), "Helvetica-Bold"),
    ("TEXTCOLOR",     (0,-1),(-1,-1), PRIMARY),
    ("ALIGN",         (2,0), (2,-1),  "RIGHT"),
    ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ("RIGHTPADDING",  (0,0), (-1,-1), 10),
    ("TOPPADDING",    (0,0), (-1,-1), 8),
    ("BOTTOMPADDING", (0,0), (-1,-1), 8),
]))
story.append(t)
story.append(Spacer(1, 0.4*cm))

story.append(Paragraph("Projeção de Receita (exemplo com 5 marinas)", st_h2))
rev_data = [
    ["Marina",               "Plano",    "Mensalidade"],
    ["Marina Porto Belo",    "Pro",       "R$ 1.000/mês"],
    ["Marina Angra",         "Pro",       "R$ 1.000/mês"],
    ["Marina Búzios",        "Starter",   "R$ 700/mês"],
    ["Marina Paraty",        "Pro",       "R$ 1.000/mês"],
    ["Marina Cabo Frio",     "Starter",   "R$ 700/mês"],
    ["RECEITA TOTAL",        "—",         "R$ 4.400/mês"],
    ["Custo infraestrutura", "—",         "R$ 80/mês"],
    ["MARGEM",               "—",         "R$ 4.320/mês (98%)"],
]
t = Table(rev_data, colWidths=[7*cm, 3.5*cm, 6*cm])
t.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
    ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
    ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
    ("FONTSIZE",      (0,0), (-1,-1), 10.5),
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("ROWBACKGROUNDS",(0,1), (-1,-3), [colors.white, LIGHT]),
    ("BACKGROUND",    (0,-3),(-1,-3), colors.HexColor("#fef9c3")),
    ("FONTNAME",      (0,-3),(-1,-3), "Helvetica-Bold"),
    ("BACKGROUND",    (0,-2),(-1,-2), colors.HexColor("#fee2e2")),
    ("BACKGROUND",    (0,-1),(-1,-1), colors.HexColor("#dcfce7")),
    ("FONTNAME",      (0,-2),(-1,-1), "Helvetica-Bold"),
    ("ALIGN",         (2,0), (2,-1),  "RIGHT"),
    ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ("RIGHTPADDING",  (0,0), (-1,-1), 10),
    ("TOPPADDING",    (0,0), (-1,-1), 8),
    ("BOTTOMPADDING", (0,0), (-1,-1), 8),
]))
story.append(t)
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 10 — PROCESSO DE ATUALIZAÇÃO
# ════════════════════════════════════════════════════════════════════
section("10", "Processo de Atualização")

story.append(Paragraph("A maior vantagem do SaaS: atualiza todos de uma vez", st_h2))
info_box(
    "<b>Com a arquitetura multi-tenant, um único deploy atualiza TODAS as marinas "
    "simultaneamente.</b> Não é mais necessário acessar cada servidor de cliente — "
    "basta fazer um git push ou acionar o deploy no Railway/Render.",
    bg=GREEN_L, border=GREEN_B)

story.append(Paragraph("Fluxo de atualização SaaS (Railway/Render)", st_h2))
code_block(
"""# Desenvolvedor faz commit e push
git add . && git commit -m "feat: novo módulo de relatórios"
git push origin main

# Railway/Render detecta o push automaticamente
# Build do Dockerfile em ~60 segundos
# Deploy sem downtime (rolling update)
# Todas as marinas recebem a atualização simultaneamente""")

story.append(Paragraph("O que é atualizado automaticamente", st_h2))
info_box(
    "Os itens abaixo são gerenciados pelo sistema no startup — "
    "<b>nenhuma intervenção manual é necessária:</b>",
    bg=GREEN_L, border=GREEN_B)
auto_data = [
    ["O quê",                          "Mecanismo"],
    ["Novas tabelas no banco",          "001_initial.sql rodado por runMigrations() no boot"],
    ["Tabelas existentes com novas colunas","Arquivo de migração 002_*.sql — aplicado uma vez"],
    ["Novos dados de configuração",     "seedTenant() idempotente — INSERT ON CONFLICT DO NOTHING"],
    ["Novas permissões de perfil",      "seedDefaultPermissions() — inserção segura"],
    ["Alterações no frontend",          "frontend.html substituído — sem rebuild, sem cache"],
    ["Novo tenant criado após update",  "provisionTenant() aplica todas as migrações disponíveis"],
]
data_table(auto_data[0], auto_data[1:], [5.5*cm, 11*cm])
story.append(PageBreak())

story.append(Paragraph("Atualização em VPS — Script Automático", st_h2))
story.append(Paragraph(
    "Para servidores VPS, o script <font face='Courier'>update.sh</font> realiza "
    "todo o processo com segurança em aproximadamente 45 segundos:", st_body))
steps_data = [
    ["1", "Verifica",   "Node.js 20+, git, PM2 e variáveis de ambiente"],
    ["2", "Backup",     "pg_dump do PostgreSQL com timestamp (retém 30 dias)"],
    ["3", "Fetch",      "git fetch + exibe commits novos disponíveis"],
    ["4", "Pull",       "git pull origin main — atualiza código"],
    ["5", "npm install","Instala/atualiza dependências npm (ex: nova versão de postgres.js)"],
    ["6", "Valida",     "node --check server.js — reverte se houver erro de sintaxe"],
    ["7", "Restart",    "pm2 restart marina-one --update-env"],
    ["8", "Health",     "Checa /api/version em loop até confirmar resposta"],
    ["9", "Resumo",     "Exibe versão anterior → versão nova + hash do commit"],
]
t = Table(steps_data, colWidths=[0.7*cm, 2.5*cm, 13.3*cm])
t.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (0,-1), PRIMARY),
    ("TEXTCOLOR",     (0,0), (0,-1), colors.white),
    ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
    ("ALIGN",         (0,0), (0,-1), "CENTER"),
    ("BACKGROUND",    (1,0), (1,-1), LIGHT),
    ("FONTNAME",      (1,0), (1,-1), "Helvetica-Bold"),
    ("TEXTCOLOR",     (1,0), (1,-1), ACCENT),
    ("FONTSIZE",      (0,0), (-1,-1), 9.5),
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ("TOPPADDING",    (0,0), (-1,-1), 6),
    ("BOTTOMPADDING", (0,0), (-1,-1), 6),
]))
story.append(t)
story.append(Spacer(1, 0.3*cm))
code_block("cd ~/marina-one && bash update.sh")

story.append(Paragraph("Endpoint /api/version", st_h2))
code_block(
"""{
  "version":    "2.0.0",
  "git_hash":   "4079f3b",
  "build_date": "2025-04-28",
  "node":       "v20.12.0",
  "uptime_sec": 3842,
  "saas":       true
}""", small=True)
story.append(PageBreak())

story.append(Paragraph("Rollback de Emergência", st_h2))
info_box(
    "<b>Atenção:</b> execute o rollback apenas se o sistema apresentar falha crítica "
    "após atualização. Para SaaS gerenciado (Railway), basta reverter o deploy na interface web.",
    bg=WARN_L, border=WARN_B)
code_block(
"""# VPS — reverter código
pm2 stop marina-one
git log --oneline -5          # identificar hash anterior
git checkout <hash-anterior>  # ex: git checkout a1b2c3d
npm install
pm2 restart marina-one

# Se houve migração de banco (ex: nova coluna), reverter schema manualmente
# psql $DATABASE_URL -c "ALTER TABLE marina_porto-belo.users DROP COLUMN nova_coluna;" """, small=True)

story.append(Paragraph("Política de Versionamento (Semantic Versioning)", st_h2))
ver_data = [
    ["Versão",         "Exemplo", "Quando ocorre",                     "Ação necessária"],
    ["PATCH (x.x.+1)", "2.0.1",  "Bug fix, ajuste visual",            "Atualização automática segura"],
    ["MINOR (x.+1.0)", "2.1.0",  "Nova feature, schema additive",     "Migrações aplicadas no boot"],
    ["MAJOR (+1.0.0)", "3.0.0",  "Quebra de arquitetura / schema",    "Instruções específicas na release"],
]
data_table(ver_data[0], ver_data[1:], [3*cm, 1.8*cm, 5.5*cm, 6.2*cm])
story.append(Paragraph(
    "Todas as versões são documentadas em <font face='Courier'>CHANGELOG.md</font> com data, tipo e descrição.", st_note))
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 11 — ESCALABILIDADE E ROADMAP
# ════════════════════════════════════════════════════════════════════
section("11", "Escalabilidade e Roadmap")

story.append(Paragraph("Limites e Capacidade", st_h2))
scale_data = [
    ["Métrica",                  "Valor estimado",            "Observação"],
    ["Tenants simultâneos",      "Ilimitado",                 "Cada schema é isolado — sem interferência"],
    ["Usuários por tenant",      "10–50 simultâneos",         "Limitado pela instância Node.js (single-thread)"],
    ["Armazenamento por tenant", "~50MB para 1000 clientes",  "PostgreSQL comprime e indexa eficientemente"],
    ["Conexões DB",              "Até 10 por tenant (pool)",  "Configurável em src/db/pool.js"],
    ["Uptime esperado",          ">99.9% (Railway/Neon)",     "SLAs dos provedores gerenciados"],
]
data_table(scale_data[0], scale_data[1:], [4.5*cm, 4.5*cm, 7.5*cm])

story.append(Paragraph("Quando escalar horizontalmente", st_h2))
story.append(Paragraph(
    "Para carga muito alta (>50 usuários simultâneos por tenant), recomenda-se:", st_body))
bullet("Aumentar o pool de conexões por tenant em <font face='Courier'>src/db/pool.js</font>")
bullet("Adicionar um segundo processo Node.js atrás de um load balancer (NGINX upstream)")
bullet("Migrar o PostgreSQL para Neon ou RDS com réplicas de leitura")
bullet("Contratar o <b>plano de personalização</b> para essas evoluções (R$ 150/h)")
story.append(Spacer(1, 0.35*cm))

story.append(Paragraph("Roadmap Sugerido", st_h2))
road_data = [
    ["Fase",  "Entregável",                              "Estimativa"],
    ["Atual", "SaaS multi-tenant PostgreSQL — v2.0",    "Concluído"],
    ["v2.1",  "App mobile PWA + notificações push",      "3–4 semanas"],
    ["v2.2",  "Relatórios PDF automáticos por email",    "2–3 semanas"],
    ["v2.3",  "Integração PIX via API (Efí/Gerencianet)","3–5 semanas"],
    ["v3.0",  "Marketplace: marinas no mesmo domínio",   "2–3 meses"],
]
t = Table(road_data, colWidths=[1.8*cm, 9.5*cm, 5.2*cm])
t.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
    ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
    ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
    ("FONTSIZE",      (0,0), (-1,-1), 10),
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, LIGHT]),
    ("BACKGROUND",    (0,1), (-1,1),  colors.HexColor("#dcfce7")),
    ("FONTNAME",      (0,1), (-1,1),  "Helvetica-Bold"),
    ("ALIGN",         (0,0), (0,-1),  "CENTER"),
    ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ("TOPPADDING",    (0,0), (-1,-1), 7),
    ("BOTTOMPADDING", (0,0), (-1,-1), 7),
]))
story.append(t)
story.append(PageBreak())

# ════════════════════════════════════════════════════════════════════
#  SEÇÃO 12 — SUPORTE E CONTATO
# ════════════════════════════════════════════════════════════════════
section("12", "Suporte e Contato")

plans = [
    ["Plano",                 "Valor",               "Descrição"],
    ["Implantação SaaS",      "R$ 3.000 (único)",    "Provisionamento completo do ambiente multi-tenant, domínio e HTTPS"],
    ["Manutenção Mensal",     "R$ 1.000 / mês",      "Hospedagem, atualizações de todas as marinas e suporte"],
    ["Nova Marina (tenant)",  "R$ 500 (único)",      "Provisionamento de novo tenant, personalização inicial e onboarding"],
    ["Personalização",        "R$ 150 / hora",       "Desenvolvimento de funcionalidades específicas e integrações"],
]
t = Table(plans, colWidths=[4.5*cm, 3.5*cm, 8.5*cm])
t.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (-1,0),  PRIMARY),
    ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
    ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
    ("FONTSIZE",      (0,0), (-1,-1), 10.5),
    ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ("INNERGRID",     (0,0), (-1,-1), 0.5, BORDER),
    ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, LIGHT]),
    ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ("TOPPADDING",    (0,0), (-1,-1), 9),
    ("BOTTOMPADDING", (0,0), (-1,-1), 9),
]))
story.append(t)
story.append(Spacer(1, 0.7*cm))

contact_card = Table([[Paragraph(
    "<font color='white' size='12'><b>Contato</b></font><br/><br/>"
    "<font color='white' size='11'><b>Arthur Noli</b></font><br/>"
    "<font color='white' size='10'>rj.madmax@gmail.com</font><br/><br/>"
    "<font color='#93c5fd' size='9'>SaaS Owner · Marina One</font>",
    st_body)]], colWidths=[16.3*cm])
contact_card.setStyle(TableStyle([
    ("BACKGROUND",    (0,0), (-1,-1), PRIMARY),
    ("LEFTPADDING",   (0,0), (-1,-1), 24),
    ("RIGHTPADDING",  (0,0), (-1,-1), 24),
    ("TOPPADDING",    (0,0), (-1,-1), 20),
    ("BOTTOMPADDING", (0,0), (-1,-1), 20),
]))
story.append(contact_card)

# ════════════════════════════════════════════════════════════════════
#  BUILD
# ════════════════════════════════════════════════════════════════════
doc.build(story)
print("OK:", OUT)
