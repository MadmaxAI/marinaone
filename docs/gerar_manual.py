
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
    """Bloco de cabeçalho de seção com fundo azul."""
    data = [[Paragraph(f'<font color="white"><b>Seção {num}</b></font>', S_BADGE),
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
        ('ROUNDEDCORNERS', [6, 6, 6, 6]),
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
        ('ROUNDEDCORNERS', [4,4,4,4]),
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
    elems.append(Paragraph(f'<b>Passo {num} — {title}</b>', S_H2))
    elems += code_block(lines)
    return elems

def checklist_item(text, done=False):
    mark = '&#9745;' if done else '&#9744;'
    return Paragraph(f'{mark} &nbsp;{text}', S_BULLET)

# ── CAPA ──────────────────────────────────────────────────────────────────────
def build_cover():
    cover = Table(
        [[Paragraph('⚓', ParagraphStyle('ico', fontSize=60, textColor=BRANCO, alignment=TA_CENTER))],
         [Spacer(1, 20)],
         [Paragraph('Marina One', S_TITULO)],
         [Paragraph('Sistema de Gestão Integrada de Marina', S_SUB)],
         [Spacer(1, 30)],
         [HRFlowable(width='60%', color=colors.HexColor('#3b82f6'), thickness=2)],
         [Spacer(1, 30)],
         [Paragraph('Manual de Implantação', ParagraphStyle('mt', fontSize=20, textColor=BRANCO,
                    alignment=TA_CENTER, fontName='Helvetica-Bold', leading=28))],
         [Spacer(1, 16)],
         [Paragraph('Versão 1.0 &nbsp;·&nbsp; 2025', S_VERSION)],
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
    # Wrap in a full-page-height table
    page_cover = Table([[cover]], colWidths=[16.5*cm], rowHeights=[22*cm])
    page_cover.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), AZUL),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
    ]))
    return [page_cover, PageBreak()]

# ── SUMÁRIO ───────────────────────────────────────────────────────────────────
def build_toc():
    secoes = [
        ('1', 'Visão Geral do Sistema'),
        ('2', 'Requisitos de Infraestrutura'),
        ('3', 'Licenças e Dependências'),
        ('4', 'Passo a Passo de Implantação'),
        ('5', 'Checklist Pré-Entrega'),
        ('6', 'Custos de Operação Mensais'),
        ('7', 'Escalabilidade'),
        ('8', 'Suporte e Contato'),
    ]
    elems = []
    elems.append(Paragraph('Sumário', S_TOC_H))
    elems.append(HRFlowable(width='100%', color=AZUL_LIGHT, thickness=1))
    elems.append(Spacer(1, 12))
    for num, title in secoes:
        row = Table([[
            Paragraph(f'<b>Seção {num}</b>', ParagraphStyle('tn', fontSize=10, textColor=AZUL_LIGHT, fontName='Helvetica-Bold')),
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

# ── CONTEÚDO ──────────────────────────────────────────────────────────────────
def build_body():
    E = []

    # ── S1 — VISÃO GERAL ────────────────────────────────────────────────────
    E += section_header('1', 'Visão Geral do Sistema')
    E += info_box('<b>Marina One</b> é um sistema SaaS de gestão integrada para marinas, '
                  'desenvolvido em Node.js com banco de dados SQLite. Arquitetura leve, '
                  'sem dependências pagas, pronto para produção com um único comando.')

    E.append(Paragraph('<b>Stack Tecnológico</b>', S_H2))
    badges = [
        ('Node.js v20 LTS', AZUL),
        ('SQLite built-in', colors.HexColor('#0f766e')),
        ('Chart.js', colors.HexColor('#7c3aed')),
        ('HTML5 / CSS3 / JS', colors.HexColor('#b45309')),
    ]
    badge_cells = []
    for label, color in badges:
        cell = Table([[Paragraph(label, S_BADGE)]], colWidths=[3.8*cm])
        cell.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), color),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('ROUNDEDCORNERS', [4,4,4,4]),
        ]))
        badge_cells.append(cell)
    badge_row = Table([badge_cells], colWidths=[4*cm]*4)
    badge_row.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
    E.append(badge_row)
    E.append(Spacer(1,10))

    E.append(Paragraph('<b>Módulos do Sistema</b>', S_H2))
    modulos = [
        ['Dashboard', 'Fila de Operações', 'Clientes', 'Embarcações'],
        ['Vagas', 'Contratos', 'Financeiro', 'Loja / PDV'],
        ['Manutenção', 'Analytics', 'Alertas', 'Configurações'],
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

    # ── S2 — INFRAESTRUTURA ─────────────────────────────────────────────────
    E += section_header('2', 'Requisitos de Infraestrutura')

    E.append(Paragraph('Opção A — VPS em Nuvem (Recomendada)', S_H2))
    E += mk_table(
        ['Recurso', 'Especificação', 'Custo Estimado'],
        [
            ['Servidor VPS', '2 vCPU · 2 GB RAM · 40 GB SSD', 'R$ 50–120/mês'],
            ['Domínio', 'Ex: gestao.marinacliente.com.br', 'R$ 40–60/ano'],
            ['SSL (HTTPS)', 'Let\'s Encrypt (automático)', 'Gratuito'],
            ['Backup automático', 'Snapshot diário no provedor', 'R$ 10–30/mês'],
        ],
        [5*cm, 7*cm, 4.5*cm]
    )
    E.append(Paragraph('<b>Provedores recomendados:</b> Hostinger VPS · DigitalOcean · Vultr · AWS Lightsail', S_BODY))
    E.append(Spacer(1, 10))

    E.append(Paragraph('Opção B — Servidor Local na Marina', S_H2))
    E += info_box('Indicado para marinas com <b>internet instável</b>. O sistema roda internamente '
                  'e o acesso remoto é feito via <b>Tailscale</b> ou <b>Cloudflare Tunnel</b> (ambos gratuitos).')
    E += mk_table(
        ['Item', 'Especificação', 'Custo'],
        [
            ['Mini PC (Intel NUC ou similar)', '4 GB RAM · SSD 120 GB', 'R$ 800–1.500 (único)'],
            ['Acesso remoto', 'Tailscale ou Cloudflare Tunnel', 'Gratuito'],
            ['Nobreak (recomendado)', '600VA ou superior', 'R$ 200–400 (único)'],
        ],
        [6*cm, 6.5*cm, 4*cm]
    )
    E.append(PageBreak())

    # ── S3 — LICENÇAS ───────────────────────────────────────────────────────
    E += section_header('3', 'Licenças e Dependências')
    E += info_box('&#9989; <b>Custo total de licenças de software: R$ 0,00.</b> '
                  'Todo o stack é open source e de uso livre, inclusive para fins comerciais.')
    E += mk_table(
        ['Componente', 'Licença', 'Uso', 'Custo'],
        [
            ['Node.js v20 LTS', 'MIT', 'Runtime do servidor', 'Gratuito'],
            ['node:sqlite (built-in)', 'MIT', 'Banco de dados embutido', 'Gratuito'],
            ['Chart.js (CDN)', 'MIT', 'Gráficos e analytics', 'Gratuito'],
            ['Ubuntu 22.04 LTS', 'Free / GPL', 'Sistema operacional', 'Gratuito'],
            ['NGINX', 'BSD', 'Proxy reverso + HTTPS', 'Gratuito'],
            ['PM2', 'AGPL', 'Gerenciador de processo', 'Gratuito'],
            ['Let\'s Encrypt / Certbot', 'Apache 2.0', 'Certificado SSL', 'Gratuito'],
        ],
        [5*cm, 2.8*cm, 5*cm, 3.2*cm]
    )
    E.append(PageBreak())

    # ── S4 — IMPLANTAÇÃO ────────────────────────────────────────────────────
    E += section_header('4', 'Passo a Passo de Implantação')

    E += step_block('1', 'Preparar o Servidor',
        ['$ sudo apt update &amp;&amp; sudo apt upgrade -y',
         '$ curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -',
         '$ sudo apt install -y nodejs',
         '$ node -v   # Esperado: v20.x.x'])

    E += step_block('2', 'Enviar os Arquivos do Sistema',
        ['# Via SCP (transferência direta):',
         '$ scp -r ./marina-one usuario@IP_SERVIDOR:/home/usuario/marina-one',
         '',
         '# Via Git (recomendado para atualizações futuras):',
         '$ git clone https://repositorio/marina-one.git'])

    E += step_block('3', 'Configurar PM2 — Processo Sempre Online',
        ['$ sudo npm install -g pm2',
         '$ cd /home/usuario/marina-one',
         '$ pm2 start server.js --name marina-one',
         '$ pm2 startup    # Configura para iniciar com o SO',
         '$ pm2 save       # Salva a configuração'])

    E.append(PageBreak())

    E += step_block('4', 'Configurar NGINX + HTTPS (SSL Gratuito)',
        ['$ sudo apt install -y nginx certbot python3-certbot-nginx',
         '',
         '# Criar arquivo de configuração do site:',
         '$ sudo nano /etc/nginx/sites-available/marina-one',
         '',
         '  server {',
         '    server_name gestao.marinacliente.com.br;',
         '    location / {',
         '      proxy_pass http://localhost:3000;',
         '      proxy_set_header Host $host;',
         '    }',
         '  }',
         '',
         '$ sudo ln -s /etc/nginx/sites-available/marina-one /etc/nginx/sites-enabled/',
         '$ sudo nginx -t &amp;&amp; sudo systemctl reload nginx',
         '$ sudo certbot --nginx -d gestao.marinacliente.com.br'])

    E += step_block('5', 'Backup Automático Diário',
        ['# Criar script de backup:',
         '$ nano /home/usuario/backup-marina.sh',
         '',
         '  #!/bin/bash',
         '  DATE=$(date +%Y-%m-%d)',
         '  cp marina.db /backups/marina-$DATE.db',
         '  find /backups/ -name "*.db" -mtime +30 -delete',
         '',
         '$ chmod +x backup-marina.sh',
         '$ crontab -e',
         '  # Adicionar: 0 2 * * * /home/usuario/backup-marina.sh'])

    E += step_block('6', 'Personalização para o Cliente',
        ['# No arquivo server.js — trocar credenciais padrão:',
         "  ['admin@marina.com', 'marina123']",
         "  # Alterar para dados reais do cliente",
         '',
         '# No frontend.html — personalizar nome da marina',
         '# Acessar Configuracoes > Ajustar horarios de operacao',
         '# Criar usuarios iniciais para a equipe'])

    E.append(PageBreak())

    # ── S5 — CHECKLIST ──────────────────────────────────────────────────────
    E += section_header('5', 'Checklist Pré-Entrega')
    itens = [
        'Domínio apontando corretamente para o IP do servidor',
        'HTTPS funcionando (cadeado verde no navegador)',
        'Credenciais padrão de administrador substituídas',
        'Nome e informações da marina personalizados',
        'Backup automático configurado e testado',
        'PM2 reiniciando automaticamente após reboot do servidor',
        'Firewall configurado: ufw allow 80,443,22/tcp',
        'Sistema testado em celular (responsividade mobile)',
        'Usuários iniciais criados para toda a equipe',
        'Demonstração completa realizada com o cliente',
        'Treinamento básico ministrado para os operadores',
        'Documentação de acesso entregue ao responsável',
    ]
    for item in itens:
        E.append(checklist_item(item))
        E.append(Spacer(1, 4))
    E.append(PageBreak())

    # ── S6 — CUSTOS ─────────────────────────────────────────────────────────
    E += section_header('6', 'Custos de Operação Mensais')
    E += mk_table(
        ['Item', 'Descrição', 'Custo Mensal'],
        [
            ['VPS (servidor)', 'Hostinger / DigitalOcean / Vultr', 'R$ 50–120'],
            ['Domínio (pro-rata)', '.com.br ou .com', 'R$ 5'],
            ['SSL (Let\'s Encrypt)', 'Renovação automática gratuita', 'R$ 0'],
            ['Licenças de software', 'Todas MIT/Open Source', 'R$ 0'],
            ['TOTAL INFRAESTRUTURA', '', 'R$ 55–125'],
        ],
        [5*cm, 7*cm, 4.5*cm]
    )
    E += info_box('<b>Observação:</b> O custo real para o cliente é a mensalidade de manutenção '
                  'contratada com o fornecedor (R$ 1.000/mês), que <b>já inclui</b> a hospedagem, '
                  'monitoramento, atualizações e suporte técnico.')
    E.append(PageBreak())

    # ── S7 — ESCALABILIDADE ─────────────────────────────────────────────────
    E += section_header('7', 'Escalabilidade')
    E += info_box('O sistema utiliza <b>SQLite</b>, ideal para até ~10 usuários simultâneos '
                  'e volumes de até milhares de registros. Para marinas de grande porte, '
                  'recomenda-se migrar para <b>PostgreSQL</b> — o código do server.js '
                  'suporta essa transição com pequenas alterações nas queries SQL.')
    E.append(Paragraph('<b>Quando escalar:</b>', S_H2))
    for item in [
        'Mais de 10 usuários simultâneos intensos',
        'Volume de pedidos/operações acima de 500/dia',
        'Necessidade de relatórios em tempo real com alta concorrência',
        'Integração com sistemas externos (ERP, contabilidade, etc.)',
    ]:
        E.append(bullet(item))
    E.append(Spacer(1,10))
    E.append(Paragraph('Contrate o plano de <b>personalização por hora (R$ 150/h)</b> '
                        'para executar a migração sem interrupção do serviço.', S_BODY))
    E.append(PageBreak())

    # ── S8 — SUPORTE ────────────────────────────────────────────────────────
    E += section_header('8', 'Suporte e Contato')

    planos = [
        ['Implantação', 'R$ 3.000', 'Pagamento único', 'Configuração completa, personalização inicial,\ntreinamento da equipe e go-live supervisionado'],
        ['Manutenção Mensal', 'R$ 1.000/mês', 'Recorrente', 'Hospedagem, monitoramento 24/7, atualizações\ndo sistema e suporte técnico ilimitado'],
        ['Personalização', 'R$ 150/hora', 'Sob demanda', 'Novos módulos, integrações, relatórios\ncustomizados e ajustes específicos'],
    ]
    E += mk_table(
        ['Plano', 'Valor', 'Cobrança', 'Inclui'],
        planos,
        [3.5*cm, 3*cm, 3*cm, 7*cm]
    )
    E.append(Spacer(1,10))

    contact = Table([
        [Paragraph('<b>Arthur Noli</b>', ParagraphStyle('cn', fontSize=13, textColor=AZUL,
                   fontName='Helvetica-Bold'))],
        [Paragraph('Especialista em Sistemas de Gestão para Marinas', S_BODY)],
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
    # Header bar
    canvas.setFillColor(AZUL)
    canvas.rect(0, H - 1*cm, W, 1*cm, fill=1, stroke=0)
    canvas.setFillColor(BRANCO)
    canvas.setFont('Helvetica-Bold', 9)
    canvas.drawString(2*cm, H - 0.65*cm, 'Marina One — Manual de Implantação')
    canvas.setFont('Helvetica', 9)
    canvas.drawRightString(W - 2*cm, H - 0.65*cm, 'Versão 1.0 · 2025')
    # Footer
    canvas.setFillColor(CINZA)
    canvas.setFont('Helvetica', 8)
    canvas.drawCentredString(W/2, 0.7*cm, f'Página {doc.page}')
    canvas.setFillColor(CINZA_LIGHT)
    canvas.rect(2*cm, 0.5*cm, W - 4*cm, 0.02*cm, fill=1, stroke=0)
    canvas.restoreState()

# ── BUILD ─────────────────────────────────────────────────────────────────────
def main():
    doc = SimpleDocTemplate(
        OUT, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        title='Manual de Implantação — Marina One',
        author='Arthur Noli',
        subject='Sistema de Gestão Integrada de Marina',
    )
    story = []
    story += build_cover()
    story += build_toc()
    story += build_body()

    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    print(f'PDF gerado: {OUT}')

if __name__ == '__main__':
    main()
