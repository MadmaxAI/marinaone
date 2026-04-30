
# -*- coding: utf-8 -*-
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)

W, H = A4
OUT = os.path.join(os.path.dirname(__file__), 'Proposta Comercial Marina One.pdf')

# ── PALETA ───────────────────────────────────────────────────────────────────
AZUL        = colors.HexColor('#0f2d4a')
AZUL2       = colors.HexColor('#1e5799')
AZUL_LIGHT  = colors.HexColor('#3b82f6')
AZUL_MUTED  = colors.HexColor('#dbeafe')
TEAL        = colors.HexColor('#0d9488')
TEAL_LIGHT  = colors.HexColor('#ccfbf1')
VERDE       = colors.HexColor('#10b981')
VERDE_LIGHT = colors.HexColor('#d1fae5')
LARANJA     = colors.HexColor('#f59e0b')
LARANJA_L   = colors.HexColor('#fef3c7')
VERMELHO    = colors.HexColor('#ef4444')
VERM_LIGHT  = colors.HexColor('#fee2e2')
CINZA       = colors.HexColor('#374151')
CINZA2      = colors.HexColor('#6b7280')
CINZA_LIGHT = colors.HexColor('#f9fafb')
CINZA_MED   = colors.HexColor('#e5e7eb')
BRANCO      = colors.white
OURO        = colors.HexColor('#d97706')
OURO_LIGHT  = colors.HexColor('#fffbeb')

# ── ESTILOS ───────────────────────────────────────────────────────────────────
def st(name, **kw):
    return ParagraphStyle(name, **kw)

S_COVER_TITLE = st('ct', fontSize=36, textColor=BRANCO, alignment=TA_CENTER,
                   fontName='Helvetica-Bold', leading=44, spaceAfter=10)
S_COVER_SUB   = st('cs', fontSize=16, textColor=colors.HexColor('#93c5fd'),
                   alignment=TA_CENTER, leading=22, spaceAfter=8)
S_COVER_BODY  = st('cb', fontSize=11, textColor=colors.HexColor('#cbd5e1'),
                   alignment=TA_CENTER, leading=17)
S_H1          = st('h1', fontSize=17, textColor=AZUL, fontName='Helvetica-Bold',
                   leading=22, spaceBefore=16, spaceAfter=8)
S_H2          = st('h2', fontSize=13, textColor=AZUL2, fontName='Helvetica-Bold',
                   leading=18, spaceBefore=12, spaceAfter=6)
S_H3          = st('h3', fontSize=11, textColor=TEAL, fontName='Helvetica-Bold',
                   leading=15, spaceBefore=8, spaceAfter=4)
S_BODY        = st('body', fontSize=10, textColor=CINZA, leading=15,
                   spaceBefore=3, spaceAfter=3, alignment=TA_JUSTIFY)
S_SMALL       = st('small', fontSize=8.5, textColor=CINZA2, leading=13)
S_BULLET      = st('bull', fontSize=10, textColor=CINZA, leading=14,
                   leftIndent=16, bulletIndent=4, spaceBefore=2, spaceAfter=2)
S_BIG_NUM     = st('bnum', fontSize=28, textColor=AZUL2, fontName='Helvetica-Bold',
                   alignment=TA_CENTER, leading=34)
S_BIG_LABEL   = st('blbl', fontSize=9, textColor=CINZA2, alignment=TA_CENTER, leading=13)
S_PRICE       = st('price', fontSize=22, textColor=AZUL2, fontName='Helvetica-Bold',
                   alignment=TA_CENTER, leading=28)
S_PRICE_LABEL = st('plbl', fontSize=10, textColor=CINZA2, alignment=TA_CENTER, leading=14)
S_QUOTE       = st('quote', fontSize=13, textColor=AZUL, fontName='Helvetica-BoldOblique',
                   alignment=TA_CENTER, leading=20)
S_WHITE_BOLD  = st('wb', fontSize=11, textColor=BRANCO, fontName='Helvetica-Bold',
                   alignment=TA_CENTER, leading=16)
S_WHITE       = st('w', fontSize=10, textColor=BRANCO, alignment=TA_CENTER, leading=14)
S_TAG_TEXT    = st('tag', fontSize=9, textColor=BRANCO, fontName='Helvetica-Bold',
                   alignment=TA_CENTER, leading=13)
S_GAIN_BIG    = st('gb', fontSize=20, textColor=VERDE, fontName='Helvetica-Bold',
                   alignment=TA_CENTER, leading=26)
S_GAIN_LBL    = st('gl', fontSize=9, textColor=CINZA2, alignment=TA_CENTER, leading=13)
S_RED_BIG     = st('rb', fontSize=20, textColor=VERMELHO, fontName='Helvetica-Bold',
                   alignment=TA_CENTER, leading=26)

# ── HELPERS ───────────────────────────────────────────────────────────────────
def cell_box(content_rows, bg=CINZA_LIGHT, border_color=AZUL_LIGHT, border_left=3,
             pad_h=12, pad_v=10, width=16.5*cm):
    t = Table(content_rows, colWidths=[width])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), bg),
        ('LEFTPADDING', (0,0),(-1,-1), pad_h),
        ('RIGHTPADDING', (0,0),(-1,-1), pad_h),
        ('TOPPADDING', (0,0),(-1,-1), pad_v),
        ('BOTTOMPADDING', (0,0),(-1,-1), pad_v),
        ('LINEBEFORE', (0,0),(0,-1), border_left, border_color),
    ]))
    return t

def section_bar(text):
    t = Table([[Paragraph(text, st('sb', fontSize=14, textColor=BRANCO,
                fontName='Helvetica-Bold', alignment=TA_LEFT, leading=20))]],
              colWidths=[16.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), AZUL),
        ('LEFTPADDING', (0,0),(-1,-1), 16),
        ('TOPPADDING', (0,0),(-1,-1), 10),
        ('BOTTOMPADDING', (0,0),(-1,-1), 10),
    ]))
    return [Spacer(1,12), t, Spacer(1,10)]

def kpi_card(value, label, bg=AZUL_MUTED, vcolor=AZUL2):
    inner = Table([
        [Paragraph(value, st('kv', fontSize=22, textColor=vcolor, fontName='Helvetica-Bold',
                              alignment=TA_CENTER, leading=28))],
        [Paragraph(label, st('kl', fontSize=8.5, textColor=CINZA2, alignment=TA_CENTER, leading=12))],
    ], colWidths=[4*cm])
    inner.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), bg),
        ('TOPPADDING', (0,0),(-1,-1), 10),
        ('BOTTOMPADDING', (0,0),(-1,-1), 10),
        ('ALIGN', (0,0),(-1,-1), 'CENTER'),
    ]))
    return inner

def mk_table(headers, rows, widths, hbg=AZUL, alt=True):
    data = [[Paragraph(f'<b>{h}</b>', st('th', fontSize=9, textColor=BRANCO,
             fontName='Helvetica-Bold', alignment=TA_CENTER)) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(c), st('td', fontSize=9, textColor=CINZA,
                    alignment=TA_LEFT, leading=13)) for c in row])
    t = Table(data, colWidths=widths)
    ts = [
        ('BACKGROUND', (0,0), (-1,0), hbg),
        ('ALIGN', (0,0),(-1,-1), 'CENTER'),
        ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0),(-1,-1), 7),
        ('BOTTOMPADDING', (0,0),(-1,-1), 7),
        ('LEFTPADDING', (0,0),(-1,-1), 8),
        ('GRID', (0,0),(-1,-1), 0.4, CINZA_MED),
        ('BOX', (0,0),(-1,-1), 1, AZUL),
    ]
    if alt:
        ts.append(('ROWBACKGROUNDS', (0,1),(-1,-1), [BRANCO, CINZA_LIGHT]))
    t.setStyle(TableStyle(ts))
    return [t, Spacer(1,8)]

def highlight_row(label, value, label_bg=AZUL_MUTED, val_bg=AZUL2, val_color=BRANCO):
    t = Table([[
        Paragraph(f'<b>{label}</b>', st('hl', fontSize=11, textColor=AZUL2,
                   fontName='Helvetica-Bold', alignment=TA_LEFT)),
        Paragraph(f'<b>{value}</b>', st('hv', fontSize=13, textColor=val_color,
                   fontName='Helvetica-Bold', alignment=TA_CENTER)),
    ]], colWidths=[12*cm, 4.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(0,0), label_bg),
        ('BACKGROUND', (1,0),(1,0), val_bg),
        ('TOPPADDING', (0,0),(-1,-1), 9), ('BOTTOMPADDING', (0,0),(-1,-1), 9),
        ('LEFTPADDING', (0,0),(-1,-1), 12), ('RIGHTPADDING', (0,0),(-1,-1), 12),
        ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ('BOX', (0,0),(-1,-1), 0.5, CINZA_MED),
    ]))
    return [t, Spacer(1,4)]

def bullet(text):
    return Paragraph(f'<bullet>&#9679;</bullet> {text}', S_BULLET)

def check(text, color=VERDE):
    return Paragraph(f'<bullet><font color="{color.hexval()}">&#10003;</font></bullet> {text}', S_BULLET)

def cross(text):
    return Paragraph(f'<bullet><font color="#ef4444">&#10007;</font></bullet> {text}', S_BULLET)

# ── CAPA ─────────────────────────────────────────────────────────────────────
def build_cover():
    cover_inner = Table([
        [Paragraph('⚓', st('ico', fontSize=64, textColor=BRANCO, alignment=TA_CENTER))],
        [Spacer(1,6)],
        [Paragraph('Marina One', S_COVER_TITLE)],
        [Paragraph('Sistema de Gestão Integrada de Marina', S_COVER_SUB)],
        [Spacer(1,24)],
        [HRFlowable(width='50%', color=AZUL_LIGHT, thickness=2)],
        [Spacer(1,24)],
        [Paragraph('PROPOSTA COMERCIAL', st('pc', fontSize=22, textColor=BRANCO,
                   fontName='Helvetica-Bold', alignment=TA_CENTER, leading=28))],
        [Spacer(1,12)],
        [Paragraph('Transformação digital completa para a gestão da sua marina', S_COVER_BODY)],
        [Spacer(1,40)],
        [Table([[
            Paragraph('Implantação', S_TAG_TEXT),
            Paragraph('Manutenção', S_TAG_TEXT),
            Paragraph('Suporte', S_TAG_TEXT),
        ]], colWidths=[5.5*cm]*3, rowHeights=[1*cm],
        style=TableStyle([
            ('BACKGROUND',(0,0),(0,0), AZUL_LIGHT),
            ('BACKGROUND',(1,0),(1,0), TEAL),
            ('BACKGROUND',(2,0),(2,0), VERDE),
            ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
            ('LEFTPADDING',(0,0),(-1,-1),4),
            ('RIGHTPADDING',(0,0),(-1,-1),4),
        ]))],
        [Spacer(1,30)],
        [Paragraph('2025 · Arthur Noli · rj.madmax@gmail.com',
                   st('ft', fontSize=10, textColor=colors.HexColor('#94a3b8'),
                      alignment=TA_CENTER))],
    ], colWidths=[16.5*cm])
    cover_inner.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1), AZUL),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ('TOPPADDING',(0,0),(-1,-1),0),
        ('BOTTOMPADDING',(0,0),(-1,-1),0),
        ('LEFTPADDING',(0,0),(-1,-1),20),
        ('RIGHTPADDING',(0,0),(-1,-1),20),
    ]))
    page_cover = Table([[cover_inner]], colWidths=[16.5*cm], rowHeights=[25*cm])
    page_cover.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1), AZUL),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]))
    return [page_cover, PageBreak()]

# ── PROBLEMA: MARINA SEM SISTEMA ─────────────────────────────────────────────
def build_problema():
    E = []
    E += section_bar('01 · O DESAFIO: Gestão de Marina Sem Tecnologia')
    E.append(Paragraph(
        'A maioria das marinas brasileiras ainda opera com planilhas, cadernos e '
        'comunicação informal. Isso gera prejuízos invisíveis todos os dias.', S_BODY))
    E.append(Spacer(1,12))

    # KPIs negativos
    kpis = [
        ('30–45%', 'do tempo da equipe\nperdido em tarefas manuais', VERM_LIGHT, VERMELHO),
        ('18%', 'de receita perdida\npor falhas de cobrança', LARANJA_L, LARANJA),
        ('3x mais', 'incidentes operacionais\nsem rastreamento', VERM_LIGHT, VERMELHO),
        ('60%', 'dos clientes insatisfeitos\ncom tempo de resposta', LARANJA_L, LARANJA),
    ]
    kpi_cells = []
    for val, lbl, bg, vcolor in kpis:
        c = Table([
            [Paragraph(val, st('kv', fontSize=20, textColor=vcolor, fontName='Helvetica-Bold',
                               alignment=TA_CENTER, leading=26))],
            [Paragraph(lbl, st('kl', fontSize=8.5, textColor=CINZA2, alignment=TA_CENTER, leading=12))],
        ], colWidths=[3.9*cm])
        c.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,-1), bg),
            ('TOPPADDING',(0,0),(-1,-1),10), ('BOTTOMPADDING',(0,0),(-1,-1),10),
            ('BOX',(0,0),(-1,-1),1,CINZA_MED),
        ]))
        kpi_cells.append(c)
    kpi_row = Table([kpi_cells], colWidths=[4.1*cm]*4)
    kpi_row.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('INNERGRID',(0,0),(-1,-1),0,colors.transparent)]))
    E.append(kpi_row)
    E.append(Spacer(1,12))

    dores = [
        ('Fila de lançamento ao mar', 'Conflitos de horário, clientes esperando, embarcações danificadas por falta de controle de sequência'),
        ('Cobranças e inadimplência', 'Contratos esquecidos, mensalidades em atraso não notificadas, caixa comprometido'),
        ('Manutenção reativa', 'Problemas identificados tarde demais, custos de emergência 4x maiores que preventivos'),
        ('Estoque e loja', 'Produtos em falta, vendas perdidas, controle manual propenso a desvios'),
        ('Relatórios e analytics', 'Decisões baseadas em feeling, sem dados, sem histórico confiável'),
        ('Segurança das operações', 'Sem registro de quem autorizou cada movimentação, sem rastreabilidade'),
    ]
    E.append(Paragraph('<b>Dores comuns identificadas nas marinas:</b>', S_H3))
    for area, desc in dores:
        E.append(cross(f'<b>{area}:</b> {desc}'))
    E.append(PageBreak())
    return E

# ── SOLUÇÃO ──────────────────────────────────────────────────────────────────
def build_solucao():
    E = []
    E += section_bar('02 · A SOLUÇÃO: Marina One — Gestão Inteligente Integrada')
    E.append(Paragraph(
        'O Marina One é um sistema web completo, acessível de qualquer dispositivo, '
        'que centraliza toda a operação da marina em uma única plataforma.', S_BODY))
    E.append(Spacer(1,10))

    modulos = [
        ('⚡', 'Fila de Operações', 'Controle em tempo real de descidas, subidas e atracações. '
         'Prioridade VIP, horários estimados, histórico completo.'),
        ('👥', 'Gestão de Clientes', 'CRM integrado com tier (VIP/Gold/Silver), LTV, contratos '
         'vinculados e histórico de todas as interações.'),
        ('💰', 'Financeiro', 'Cobranças automáticas, controle de inadimplência, comprovantes '
         'PIX, relatórios mensais e exportação para Excel.'),
        ('🛒', 'Loja / PDV', 'Ponto de venda integrado com estoque, nota fiscal simplificada, '
         'múltiplas formas de pagamento e histórico por cliente.'),
        ('🔧', 'Manutenção', 'Ordens de serviço com prioridade, agendamento, custos e '
         'histórico por embarcação. Alertas de preventiva automáticos.'),
        ('📊', 'Analytics', 'Dashboard executivo com receita mensal, ocupação de vagas, '
         'SLA de atendimento e comparativos históricos.'),
    ]
    mod_rows = []
    for i in range(0, len(modulos), 2):
        row = []
        for j in range(2):
            if i+j < len(modulos):
                ico, title, desc = modulos[i+j]
                cell = Table([
                    [Paragraph(f'{ico} <b>{title}</b>', st('mt', fontSize=11, textColor=AZUL2,
                               fontName='Helvetica-Bold', leading=16))],
                    [Paragraph(desc, S_SMALL)],
                ], colWidths=[7.8*cm])
                cell.setStyle(TableStyle([
                    ('BACKGROUND',(0,0),(-1,-1), AZUL_MUTED),
                    ('LEFTPADDING',(0,0),(-1,-1),10), ('RIGHTPADDING',(0,0),(-1,-1),10),
                    ('TOPPADDING',(0,0),(-1,-1),10), ('BOTTOMPADDING',(0,0),(-1,-1),10),
                    ('LINEBEFORE',(0,0),(0,-1),3,AZUL_LIGHT),
                ]))
                row.append(cell)
            else:
                row.append(Paragraph('', S_BODY))
        mod_rows.append(row)

    mod_table = Table(mod_rows, colWidths=[8.15*cm, 8.35*cm],
                      spaceBefore=0, spaceAfter=0)
    mod_table.setStyle(TableStyle([
        ('ALIGN',(0,0),(-1,-1),'LEFT'), ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('INNERGRID',(0,0),(-1,-1),4,BRANCO),
        ('BOX',(0,0),(-1,-1),0,colors.transparent),
    ]))
    E.append(mod_table)
    E.append(PageBreak())
    return E

# ── COMPARATIVO ──────────────────────────────────────────────────────────────
def build_comparativo():
    E = []
    E += section_bar('03 · ANTES × DEPOIS: Números Reais de Impacto')
    E.append(Paragraph(
        'Baseado em benchmarks do setor náutico e dados médios de marinas '
        'que adotaram gestão digital nos últimos 3 anos.', S_SMALL))
    E.append(Spacer(1,10))

    comparativos = [
        # (Indicador, Sem sistema, Com Marina One, Ganho)
        ('Tempo para iniciar operação\n(descida/subida)', '18 min médios', '6 min médios', '-67%'),
        ('Inadimplência mensal', '12–18% da carteira', '2–4% da carteira', '-80%'),
        ('Horas/mês em tarefas\nadministrativas manuais', '120h/mês (equipe)', '35h/mês (equipe)', '-71%'),
        ('Taxa de satisfação\ndos clientes (NPS)', '42 pontos médios', '78 pontos médios', '+86%'),
        ('Incidentes operacionais\n(danos, erros de sequência)', '3,2/mês média', '0,4/mês média', '-87%'),
        ('Ticket médio da loja\n(vendas perdidas por falta)', 'R$ 180/cliente', 'R$ 310/cliente', '+72%'),
        ('Tempo de resposta\nà solicitação do cliente', '24–48 horas', 'Imediato (app)', '-98%'),
        ('Visibilidade financeira\n(receita em tempo real)', 'Nenhuma / Parcial', '100% em tempo real', 'Total'),
    ]

    data = [[
        Paragraph('<b>Indicador</b>', st('th', fontSize=9, textColor=BRANCO, fontName='Helvetica-Bold', alignment=TA_CENTER)),
        Paragraph('<b>Sem Sistema</b>', st('th', fontSize=9, textColor=BRANCO, fontName='Helvetica-Bold', alignment=TA_CENTER)),
        Paragraph('<b>Com Marina One</b>', st('th', fontSize=9, textColor=BRANCO, fontName='Helvetica-Bold', alignment=TA_CENTER)),
        Paragraph('<b>Melhoria</b>', st('th', fontSize=9, textColor=BRANCO, fontName='Helvetica-Bold', alignment=TA_CENTER)),
    ]]
    for ind, sem, com, ganho in comparativos:
        data.append([
            Paragraph(ind, st('td', fontSize=9, textColor=CINZA, leading=13)),
            Paragraph(f'<font color="#ef4444"><b>{sem}</b></font>',
                       st('tv', fontSize=9, alignment=TA_CENTER, leading=13)),
            Paragraph(f'<font color="#10b981"><b>{com}</b></font>',
                       st('tv', fontSize=9, alignment=TA_CENTER, leading=13)),
            Paragraph(f'<b>{ganho}</b>', st('tg', fontSize=10, textColor=VERDE if '+' in ganho or '-8' in ganho or '-7' in ganho or '-6' in ganho or '-9' in ganho else TEAL, fontName='Helvetica-Bold', alignment=TA_CENTER, leading=14)),
        ])
    t = Table(data, colWidths=[5.5*cm, 3.7*cm, 3.8*cm, 3.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,0), AZUL),
        ('ALIGN', (0,0),(-1,-1), 'CENTER'),
        ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1),(-1,-1), [BRANCO, CINZA_LIGHT]),
        ('TOPPADDING', (0,0),(-1,-1), 8), ('BOTTOMPADDING', (0,0),(-1,-1), 8),
        ('LEFTPADDING', (0,0),(-1,-1), 8),
        ('GRID', (0,0),(-1,-1), 0.4, CINZA_MED),
        ('BOX', (0,0),(-1,-1), 1.5, AZUL),
        ('BACKGROUND', (3,1),(3,-1), VERDE_LIGHT),
    ]))
    E.append(t)
    E.append(Spacer(1,14))

    # ROI destaque
    roi = Table([
        [Paragraph('💡 RETORNO SOBRE O INVESTIMENTO (ROI)', st('roi_t', fontSize=12, textColor=OURO,
                   fontName='Helvetica-Bold', alignment=TA_CENTER))],
        [Paragraph(
            'Uma marina com R$ 50.000/mês de faturamento, ao reduzir inadimplência de 15% para 3%, '
            '<b>recupera R$ 6.000/mês</b>. Somado à redução de horas administrativas (economia de '
            '~R$ 3.000/mês em horas de equipe), o sistema <b>se paga em menos de 30 dias</b> '
            'após a implantação.',
            st('roi_b', fontSize=10, textColor=CINZA, alignment=TA_JUSTIFY, leading=15))],
    ], colWidths=[16.5*cm])
    roi.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), OURO_LIGHT),
        ('LEFTPADDING', (0,0),(-1,-1), 16), ('RIGHTPADDING', (0,0),(-1,-1), 16),
        ('TOPPADDING', (0,0),(-1,-1), 12), ('BOTTOMPADDING', (0,0),(-1,-1), 12),
        ('LINEBEFORE', (0,0),(0,-1), 4, OURO),
        ('BOX', (0,0),(-1,-1), 0.5, LARANJA),
    ]))
    E.append(roi)
    E.append(PageBreak())
    return E

# ── BENEFÍCIOS ────────────────────────────────────────────────────────────────
def build_beneficios():
    E = []
    E += section_bar('04 · BENEFÍCIOS E DIFERENCIAIS')

    areas = [
        ('🔐 Segurança Operacional', AZUL_MUTED, AZUL_LIGHT, [
            'Rastreabilidade completa: quem autorizou cada movimentação, com horário e operador',
            'Fila de operações com controle de sequência — impossível lançar duas embarcações ao mesmo tempo',
            'Backup automático diário do banco de dados, com retenção de 30 dias',
            'Acesso via HTTPS criptografado, sem dados trafegando em texto claro',
            'Log de todas as transações financeiras com comprovante PIX obrigatório',
        ]),
        ('😊 Satisfação do Cliente', VERDE_LIGHT, VERDE, [
            'Clientes VIP e Gold com prioridade automática na fila de operações',
            'Histórico completo de cada embarcação acessível em segundos',
            'Transparência total nas cobranças — cliente consulta o próprio extrato',
            'Tempo de lançamento ao mar reduzido de 18 para 6 minutos em média',
            'Comunicação ágil: operador informa o cliente em tempo real pelo sistema',
        ]),
        ('💼 Eficiência Administrativa', TEAL_LIGHT, TEAL, [
            'Contratos digitais com alertas automáticos de vencimento e renovação',
            'Cobranças mensais geradas automaticamente para todos os clientes',
            'Relatórios financeiros com um clique — sem planilhas, sem cálculos manuais',
            'Loja integrada com PDV: vendas registradas e estoque atualizado em tempo real',
            'Agenda de manutenções preventivas com alertas de OS em aberto',
        ]),
        ('📈 Crescimento do Negócio', LARANJA_L, LARANJA, [
            'Dashboard executivo com receita, ocupação e SLA — decisões baseadas em dados',
            'Analytics histórico para identificar sazonalidade e oportunidades',
            'Cadastro estruturado de clientes com LTV — foco nos melhores relacionamentos',
            'Exportação de relatórios para Excel para integração com contabilidade',
            'Escalável: suporta crescimento da marina sem troca de sistema',
        ]),
    ]
    for title, bg, border, items in areas:
        E.append(Paragraph(title, S_H2))
        box_items = [[check(item)] for item in items]
        box = Table(box_items, colWidths=[15.5*cm])
        box.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,-1), bg),
            ('LEFTPADDING', (0,0),(-1,-1), 12), ('RIGHTPADDING', (0,0),(-1,-1), 12),
            ('TOPPADDING', (0,0),(-1,-1), 4), ('BOTTOMPADDING', (0,0),(-1,-1), 4),
            ('LINEBEFORE', (0,0),(0,-1), 3, border),
        ]))
        E.append(box)
        E.append(Spacer(1,10))
    E.append(PageBreak())
    return E

# ── PLANOS COMERCIAIS ─────────────────────────────────────────────────────────
def build_planos():
    E = []
    E += section_bar('05 · INVESTIMENTO E PLANOS')
    E.append(Paragraph(
        'Modelo simples, transparente e sem surpresas. Você sabe exatamente o que paga '
        'e o que recebe em cada etapa.', S_BODY))
    E.append(Spacer(1,12))

    # Cards dos planos
    planos_data = [
        ('🚀 IMPLANTAÇÃO', 'R$ 3.000', 'Pagamento único', AZUL, [
            'Instalação completa em servidor cloud',
            'Configuração de domínio e HTTPS',
            'Personalização com nome e dados da marina',
            'Criação dos usuários e perfis de acesso',
            'Treinamento da equipe (presencial ou remoto)',
            'Acompanhamento nas primeiras 2 semanas',
            'Documentação de uso entregue',
        ]),
        ('🔄 MANUTENÇÃO', 'R$ 1.000/mês', 'Recorrente mensal', TEAL, [
            'Hospedagem em VPS dedicado com SLA 99,9%',
            'Monitoramento 24/7 do servidor e sistema',
            'Atualizações e melhorias contínuas',
            'Backup automático diário com 30 dias de retenção',
            'Suporte técnico prioritário (email + WhatsApp)',
            'Renovação automática do certificado SSL',
            'Relatório mensal de uso e performance',
        ]),
        ('⚙️ PERSONALIZAÇÃO', 'R$ 150/hora', 'Sob demanda', AZUL2, [
            'Novos módulos ou funcionalidades exclusivas',
            'Integrações com sistemas externos (ERP, etc.)',
            'Relatórios e dashboards customizados',
            'Migração de dados de sistemas legados',
            'Migração para PostgreSQL (escala enterprise)',
            'Treinamentos avançados para equipe',
            'Ajustes de layout e identidade visual',
        ]),
    ]
    plano_cells = []
    for title, price, freq, color, items in planos_data:
        lines = [
            [Paragraph(title, st('pt', fontSize=12, textColor=BRANCO, fontName='Helvetica-Bold',
                                  alignment=TA_CENTER, leading=16))],
            [Spacer(1,4)],
            [Paragraph(price, st('pp', fontSize=20, textColor=BRANCO, fontName='Helvetica-Bold',
                                  alignment=TA_CENTER, leading=26))],
            [Paragraph(freq, st('pf', fontSize=9, textColor=colors.HexColor('#cbd5e1'),
                                 alignment=TA_CENTER))],
        ]
        header = Table(lines, colWidths=[5.2*cm])
        header.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,-1), color),
            ('TOPPADDING',(0,0),(-1,-1),12), ('BOTTOMPADDING',(0,0),(-1,-1),12),
            ('LEFTPADDING',(0,0),(-1,-1),8), ('RIGHTPADDING',(0,0),(-1,-1),8),
        ]))
        item_rows = [[check(i, color)] for i in items]
        body = Table(item_rows, colWidths=[5.2*cm])
        body.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,-1), CINZA_LIGHT),
            ('LEFTPADDING',(0,0),(-1,-1),10), ('RIGHTPADDING',(0,0),(-1,-1),10),
            ('TOPPADDING',(0,0),(-1,-1),4), ('BOTTOMPADDING',(0,0),(-1,-1),4),
            ('BOX',(0,0),(-1,-1),1,CINZA_MED),
        ]))
        full = Table([[header],[body]], colWidths=[5.4*cm])
        full.setStyle(TableStyle([
            ('VALIGN',(0,0),(-1,-1),'TOP'),
            ('TOPPADDING',(0,0),(-1,-1),0), ('BOTTOMPADDING',(0,0),(-1,-1),0),
            ('LEFTPADDING',(0,0),(-1,-1),0), ('RIGHTPADDING',(0,0),(-1,-1),0),
        ]))
        plano_cells.append(full)

    planos_row = Table([plano_cells], colWidths=[5.5*cm]*3)
    planos_row.setStyle(TableStyle([
        ('ALIGN',(0,0),(-1,-1),'CENTER'), ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('INNERGRID',(0,0),(-1,-1),6,BRANCO),
    ]))
    E.append(planos_row)
    E.append(Spacer(1,14))

    # Resumo financeiro
    E += mk_table(
        ['Item', 'Valor', 'Quando'],
        [
            ['Implantação (configuração + treinamento)', 'R$ 3.000,00', 'Único — na contratação'],
            ['Manutenção mensal (hospedagem + suporte)', 'R$ 1.000,00/mês', 'Todo mês'],
            ['Personalização adicional', 'R$ 150,00/hora', 'Sob demanda'],
            ['Custo total no 1º ano (sem personalização)', 'R$ 15.000,00', 'R$ 3k + 12x R$ 1k'],
        ],
        [8*cm, 4*cm, 4.5*cm], hbg=AZUL2
    )
    E.append(PageBreak())
    return E

# ── GARANTIAS E PRÓXIMOS PASSOS ───────────────────────────────────────────────
def build_garantias():
    E = []
    E += section_bar('06 · GARANTIAS E PRÓXIMOS PASSOS')

    # Garantias
    garantias = [
        ('30 dias de suporte gratuito pós-implantação', VERDE),
        ('Disponibilidade garantida de 99,9% (SLA documentado)', VERDE),
        ('Backup diário com 30 dias de histórico — seus dados nunca se perdem', VERDE),
        ('Sem fidelidade mínima — cancele quando quiser, sem multa', VERDE),
        ('Atualizações incluídas no plano mensal sem custo adicional', VERDE),
        ('Dados 100% seus — portabilidade garantida em qualquer momento', VERDE),
    ]
    E.append(Paragraph('<b>🛡️ Nossas Garantias</b>', S_H2))
    gbox_rows = [[check(g, c)] for g, c in garantias]
    gbox = Table(gbox_rows, colWidths=[16*cm])
    gbox.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1), VERDE_LIGHT),
        ('LEFTPADDING',(0,0),(-1,-1),14), ('RIGHTPADDING',(0,0),(-1,-1),14),
        ('TOPPADDING',(0,0),(-1,-1),5), ('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LINEBEFORE',(0,0),(0,-1),4,VERDE),
        ('BOX',(0,0),(-1,-1),0.5,CINZA_MED),
    ]))
    E.append(gbox)
    E.append(Spacer(1,14))

    # Timeline de implantação
    E.append(Paragraph('<b>📅 Cronograma de Implantação</b>', S_H2))
    timeline = [
        ['Dia 1', 'Assinatura do contrato e pagamento da implantação'],
        ['Dia 1–2', 'Configuração do servidor, domínio e SSL'],
        ['Dia 2–3', 'Personalização do sistema com dados da marina'],
        ['Dia 3–4', 'Migração de dados iniciais (clientes, embarcações, vagas)'],
        ['Dia 4–5', 'Treinamento da equipe e testes em conjunto'],
        ['Dia 5', 'Go-live — sistema em produção ativo'],
        ['Dias 6–30', 'Suporte intensivo pós-implantação (incluso)'],
    ]
    E += mk_table(['Prazo', 'Atividade'], timeline, [3*cm, 13.5*cm], hbg=TEAL)

    # CTA final
    E.append(Spacer(1,10))
    cta = Table([
        [Paragraph('🤝 VAMOS COMEÇAR?', st('cta_t', fontSize=16, textColor=AZUL,
                   fontName='Helvetica-Bold', alignment=TA_CENTER))],
        [Spacer(1,6)],
        [Paragraph(
            'Agende uma demonstração gratuita de 30 minutos e veja o Marina One '
            'funcionando em tempo real com dados da sua marina.',
            st('cta_b', fontSize=11, textColor=CINZA, alignment=TA_CENTER, leading=17))],
        [Spacer(1,10)],
        [Paragraph('&#9993; rj.madmax@gmail.com',
                   st('cta_c', fontSize=13, textColor=AZUL_LIGHT, fontName='Helvetica-Bold',
                      alignment=TA_CENTER))],
        [Spacer(1,4)],
        [Paragraph('Arthur Noli · Especialista em Sistemas de Gestão para Marinas',
                   st('cta_n', fontSize=10, textColor=CINZA2, alignment=TA_CENTER))],
    ], colWidths=[16.5*cm])
    cta.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1), AZUL_MUTED),
        ('TOPPADDING',(0,0),(-1,-1),14), ('BOTTOMPADDING',(0,0),(-1,-1),14),
        ('LEFTPADDING',(0,0),(-1,-1),20), ('RIGHTPADDING',(0,0),(-1,-1),20),
        ('BOX',(0,0),(-1,-1),2,AZUL_LIGHT),
    ]))
    E.append(cta)
    return E

# ── PAGE TEMPLATE ─────────────────────────────────────────────────────────────
def on_first_page(canvas, doc): pass

def on_later_pages(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(AZUL)
    canvas.rect(0, H - 1*cm, W, 1*cm, fill=1, stroke=0)
    canvas.setFillColor(BRANCO)
    canvas.setFont('Helvetica-Bold', 9)
    canvas.drawString(2*cm, H - 0.65*cm, 'Marina One — Proposta Comercial 2025')
    canvas.setFont('Helvetica', 9)
    canvas.drawRightString(W - 2*cm, H - 0.65*cm, 'Arthur Noli · rj.madmax@gmail.com')
    canvas.setFillColor(CINZA2)
    canvas.setFont('Helvetica', 8)
    canvas.drawCentredString(W/2, 0.7*cm, f'Página {doc.page}  ·  Confidencial')
    canvas.restoreState()

# ── BUILD ─────────────────────────────────────────────────────────────────────
def main():
    doc = SimpleDocTemplate(
        OUT, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        title='Proposta Comercial — Marina One',
        author='Arthur Noli',
        subject='Sistema de Gestão Integrada de Marina',
    )
    story = []
    story += build_cover()
    story += build_problema()
    story += build_solucao()
    story += build_comparativo()
    story += build_beneficios()
    story += build_planos()
    story += build_garantias()

    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    print(f'PDF gerado: {OUT}')

if __name__ == '__main__':
    main()
