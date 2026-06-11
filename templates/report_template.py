"""
Penterous — PDF report styles, palette et layout helpers.
Design : rapport pentest professionnel — fond blanc, accents néon.
by p3nt2r0us
"""
import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, Preformatted, KeepTogether, Flowable
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.pdfgen import canvas as pdfcanvas
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False


# ── Palette ───────────────────────────────────────────────────────────────────
# Fond        : blanc pur — lisibilité maximale
# Blocs code  : noir / très sombre — contraste fort
# Accents     : néon vert / cyan pour les titres et flags
# Tableaux    : léger alternance gris clair

COLOR_PAGE      = colors.HexColor('#ffffff')   # fond de page
COLOR_COVER_BG  = colors.HexColor('#0d1b2a')   # couverture : bleu marine profond
COLOR_HDR_BG    = colors.HexColor('#0d1b2a')   # bandeau header/footer
COLOR_SECT_BG   = colors.HexColor('#0d1b2a')   # en-têtes de section
COLOR_CODE_BG   = colors.HexColor('#1a1a2e')   # fond des blocs de code
COLOR_CODE_BG2  = colors.HexColor('#12121f')   # fond script exploit

COLOR_DARK      = colors.HexColor('#0d1b2a')   # alias principal sombre
COLOR_DARK2     = colors.HexColor('#1a1a2e')
COLOR_DARK3     = colors.HexColor('#f3f4f6')   # ligne tableau paire
COLOR_DARK4     = colors.HexColor('#ffffff')   # ligne tableau impaire

COLOR_GREEN     = colors.HexColor('#00e676')   # néon vert principal
COLOR_GREEN2    = colors.HexColor('#39ff14')   # vert vif (matrix bar)
COLOR_GREEN3    = colors.HexColor('#00c853')   # vert activation

COLOR_CYAN      = colors.HexColor('#00e5ff')   # cyan électrique
COLOR_CYAN2     = colors.HexColor('#40c4ff')   # cyan clair
COLOR_BLUE      = colors.HexColor('#448aff')   # bleu accent

COLOR_YELLOW    = colors.HexColor('#ffd600')   # or
COLOR_ORANGE    = colors.HexColor('#ff6d00')   # orange
COLOR_RED       = colors.HexColor('#e53935')   # rouge
COLOR_PINK      = colors.HexColor('#f50057')

COLOR_WHITE     = colors.HexColor('#ffffff')
COLOR_OFF_WHITE = colors.HexColor('#f3f4f6')   # rangées paires tableau
COLOR_TEXT      = colors.HexColor('#1a1a2e')   # texte principal (sur blanc)
COLOR_TEXT_DIM  = colors.HexColor('#64748b')   # texte secondaire
COLOR_GRAY      = colors.HexColor('#94a3b8')   # gris moyen
COLOR_GRAY2     = colors.HexColor('#cbd5e1')   # séparateurs légers
COLOR_GRAY3     = colors.HexColor('#e2e8f0')   # grilles tableau
COLOR_ACCENT    = colors.HexColor('#00e676')   # bande accent gauche (identique GREEN)


# ── Custom Flowables ──────────────────────────────────────────────────────────

class AsciiArtBox(Flowable):
    """ASCII art centré sur fond marine, avec bordure néon."""
    def __init__(self, text, color=None, bg=None, font_size=7.5, line_height=9.5):
        Flowable.__init__(self)
        self.text = text
        self.color = color or COLOR_GREEN
        self.bg    = bg or COLOR_COVER_BG
        self.font_size   = font_size
        self.line_height = line_height
        self._lines = text.split('\n')
        self.height = len(self._lines) * line_height + 20

    def draw(self):
        w = getattr(self, '_availableWidth', 17 * cm)
        c = self.canv
        c.saveState()

        # fond
        c.setFillColor(self.bg)
        c.rect(0, 0, w, self.height, fill=1, stroke=0)

        # bordure néon verte
        c.setStrokeColor(self.color)
        c.setLineWidth(1)
        c.rect(0, 0, w, self.height, fill=0, stroke=1)

        # texte centré
        c.setFillColor(self.color)
        c.setFont("Courier-Bold", self.font_size)
        total_h = len(self._lines) * self.line_height
        y_start  = self.height - (self.height - total_h) / 2 - self.line_height + 2
        for i, line in enumerate(self._lines):
            c.drawCentredString(w / 2, y_start - i * self.line_height, line)

        c.restoreState()

    def wrap(self, availWidth, availHeight):
        self._availableWidth = availWidth
        return availWidth, self.height


class GlowLine(Flowable):
    """Ligne néon horizontale."""
    def __init__(self, width_pct=1.0, color=None, thickness=2, glow_color=None):
        Flowable.__init__(self)
        self.width_pct  = width_pct
        self.color      = color or COLOR_CYAN
        self.thickness  = thickness
        self.glow_color = glow_color
        self.height     = thickness + 6

    def draw(self):
        w = getattr(self, '_availableWidth', 17 * cm) * self.width_pct
        c = self.canv
        c.saveState()
        if self.glow_color:
            c.setStrokeColor(self.glow_color)
            c.setLineWidth(self.thickness * 3)
            c.line(0, self.thickness / 2, w, self.thickness / 2)
        c.setStrokeColor(self.color)
        c.setLineWidth(self.thickness)
        c.line(0, self.thickness / 2, w, self.thickness / 2)
        c.restoreState()

    def wrap(self, availWidth, availHeight):
        self._availableWidth = availWidth
        return availWidth, self.height


class MatrixBar(Flowable):
    """Barre décorative hex — fond sombre."""
    TEXT = "39 46 46 20 6e 65 76 65 72 20 67 69 76 65 73 20 75 70 20 7b 70 33 6e 74 65 72 6f 75 73 7d"

    def __init__(self, height=14, color=None, bg=None):
        Flowable.__init__(self)
        self.bar_height = height
        self.color = color or COLOR_GREEN2
        self.bg    = bg or COLOR_COVER_BG

    def draw(self):
        w = getattr(self, '_availableWidth', 17 * cm)
        c = self.canv
        c.saveState()
        c.setFillColor(self.bg)
        c.rect(0, 0, w, self.bar_height, fill=1, stroke=0)
        c.setFillColor(self.color)
        c.setFont("Courier", 6)
        display = (self.TEXT * 5)[:int(w / 4.2)]
        c.drawString(4, 4, display)
        c.restoreState()

    def wrap(self, availWidth, availHeight):
        self._availableWidth = availWidth
        return availWidth, self.bar_height


class FlagBox(Flowable):
    """Bannière flag capturé — fond sombre, bordure néon."""
    def __init__(self, flag_text, is_remote=False, width=None):
        Flowable.__init__(self)
        self.flag_text = flag_text
        self.is_remote = is_remote
        self._w = width
        self.height = 3.2 * cm

    def draw(self):
        w = self._w or getattr(self, '_availableWidth', 17 * cm)
        h = self.height
        c = self.canv
        c.saveState()

        border = COLOR_YELLOW if self.is_remote else COLOR_GREEN
        bg     = colors.HexColor('#1a1400') if self.is_remote else colors.HexColor('#001a0d')

        # cadre néon
        c.setFillColor(border)
        c.roundRect(0, 0, w, h, 7, fill=1, stroke=0)
        pad = 3
        c.setFillColor(bg)
        c.roundRect(pad, pad, w - 2*pad, h - 2*pad, 5, fill=1, stroke=0)

        # crochets angulaires
        c.setStrokeColor(border)
        c.setLineWidth(1.5)
        L = 14
        for x, y in [(pad+3, pad+3), (w-pad-L-3, pad+3),
                     (pad+3, h-pad-L-3), (w-pad-L-3, h-pad-L-3)]:
            c.line(x, y, x+L, y)
            c.line(x, y, x, y+L)

        # label
        label = "[ REMOTE FLAG CAPTURED ]" if self.is_remote else "[ FLAG CAPTURED ]"
        c.setFillColor(border)
        c.setFont("Courier-Bold", 8)
        c.drawCentredString(w / 2, h - pad - 15, label)

        # texte du flag
        flag_display = self.flag_text[:70] + ("..." if len(self.flag_text) > 70 else "")
        c.setFillColor(COLOR_WHITE)
        c.setFont("Courier-Bold", 13)
        c.drawCentredString(w / 2, h / 2 - 7, flag_display)

        c.restoreState()

    def wrap(self, availWidth, availHeight):
        self._availableWidth = availWidth
        return availWidth, self.height


class SkullBadge(Flowable):
    """Badge PWNED / FAILED."""
    def __init__(self, pwned=True, width=None):
        Flowable.__init__(self)
        self.pwned = pwned
        self._w    = width
        self.height = 1.4 * cm

    def draw(self):
        w = self._w or getattr(self, '_availableWidth', 17 * cm)
        h = self.height
        c = self.canv
        c.saveState()

        border = COLOR_GREEN if self.pwned else COLOR_RED
        bg     = colors.HexColor('#001a0d') if self.pwned else colors.HexColor('#1a0000')
        text   = "  >>>  P W N E D  <<<" if self.pwned else "  >>>  F A I L E D  <<<"

        c.setFillColor(border)
        c.roundRect(0, 0, w, h, 5, fill=1, stroke=0)
        pad = 2.5
        c.setFillColor(bg)
        c.roundRect(pad, pad, w - 2*pad, h - 2*pad, 3, fill=1, stroke=0)
        c.setFillColor(border)
        c.setFont("Courier-Bold", 16)
        c.drawCentredString(w / 2, h / 2 - 7, text)
        c.restoreState()

    def wrap(self, availWidth, availHeight):
        self._availableWidth = availWidth
        return availWidth, self.height


# ── Page template : fond blanc + header/footer marine ─────────────────────────

class HackerPageTemplate:
    def __init__(self, binary_name: str):
        self.binary_name = binary_name
        self._page = 0

    def __call__(self, canv, doc):
        self._page += 1
        w, h = A4
        canv.saveState()

        # ── Bandeau supérieur marine ──────────────────────────────────────
        canv.setFillColor(COLOR_HDR_BG)
        canv.rect(0, h - 1.15*cm, w, 1.15*cm, fill=1, stroke=0)

        # liseré néon sous le bandeau
        canv.setStrokeColor(COLOR_GREEN)
        canv.setLineWidth(1.5)
        canv.line(0, h - 1.15*cm, w, h - 1.15*cm)

        canv.setFillColor(COLOR_GREEN)
        canv.setFont("Courier-Bold", 7.5)
        canv.drawString(2*cm, h - 0.76*cm,
                        f"PENTEROUS  \u00b7  {self.binary_name}")
        canv.setFillColor(COLOR_GRAY)
        canv.setFont("Courier", 7)
        canv.drawRightString(w - 2*cm, h - 0.76*cm,
                             "BINARY EXPLOITATION FRAMEWORK  \u00b7  p3nt2r0us")

        # ── Bandeau inférieur marine ──────────────────────────────────────
        canv.setFillColor(COLOR_HDR_BG)
        canv.rect(0, 0, w, 0.95*cm, fill=1, stroke=0)

        # liseré néon au-dessus du footer
        canv.setStrokeColor(COLOR_CYAN)
        canv.setLineWidth(1)
        canv.line(0, 0.95*cm, w, 0.95*cm)

        canv.setFillColor(COLOR_GRAY)
        canv.setFont("Courier", 6.5)
        canv.drawString(2*cm, 0.35*cm,
                        "Generated by Penterous  \u00b7  Educational use only  \u00b7  by p3nt2r0us")
        canv.setFillColor(COLOR_CYAN)
        canv.setFont("Courier-Bold", 7)
        canv.drawRightString(w - 2*cm, 0.35*cm, f"Page  {self._page}")

        # ── Bande accent verte gauche ─────────────────────────────────────
        canv.setFillColor(COLOR_GREEN)
        canv.rect(0, 0.95*cm, 4, h - 2.1*cm, fill=1, stroke=0)

        canv.restoreState()


# ── Style builder ─────────────────────────────────────────────────────────────

def build_styles():
    styles = getSampleStyleSheet()
    C = {
        # ── Couverture
        'ascii_logo': ParagraphStyle(
            'ascii_logo', fontName='Courier-Bold', fontSize=7.5,
            textColor=COLOR_GREEN, alignment=TA_CENTER,
            spaceAfter=2, spaceBefore=0, leading=9,
        ),
        'title_main': ParagraphStyle(
            'title_main', fontName='Courier-Bold', fontSize=34,
            textColor=COLOR_GREEN, alignment=TA_CENTER,
            spaceBefore=4, spaceAfter=2, leading=40,
        ),
        'title_sub': ParagraphStyle(
            'title_sub', fontName='Courier-Bold', fontSize=12,
            textColor=COLOR_GREEN, alignment=TA_CENTER, spaceAfter=3,
        ),
        'subtitle': ParagraphStyle(
            'subtitle', fontName='Courier', fontSize=8.5,
            textColor=COLOR_GRAY, alignment=TA_CENTER, spaceAfter=12,
        ),
        # ── Corps (sur fond blanc)
        'body': ParagraphStyle(
            'body', fontName='Courier', fontSize=8.5,
            textColor=COLOR_TEXT, spaceAfter=4, leading=14,
        ),
        'body_dim': ParagraphStyle(
            'body_dim', fontName='Courier', fontSize=8,
            textColor=COLOR_TEXT_DIM, spaceAfter=3, leading=12,
        ),
        # ── Code — texte noir, sans fond coloré
        'code': ParagraphStyle(
            'code', fontName='Courier', fontSize=9,
            textColor=colors.HexColor('#000000'),
            leftIndent=10, rightIndent=6, spaceAfter=2,
            leading=13, borderPad=2,
        ),
        'code_script': ParagraphStyle(
            'code_script', fontName='Courier', fontSize=9.5,
            textColor=colors.HexColor('#000000'),
            leftIndent=14, rightIndent=14, spaceAfter=0,
            spaceBefore=0, leading=14, borderPad=10,
        ),
        'code_prompt': ParagraphStyle(
            'code_prompt', fontName='Courier', fontSize=7.5,
            textColor=COLOR_CYAN, backColor=COLOR_CODE_BG,
            leftIndent=10, rightIndent=6, spaceAfter=2,
            leading=11, borderPad=3,
        ),
        # ── Labels
        'label': ParagraphStyle(
            'label', fontName='Courier-Bold', fontSize=8.5,
            textColor=COLOR_DARK, spaceAfter=4, spaceBefore=6,
        ),
        'label_cyan': ParagraphStyle(
            'label_cyan', fontName='Courier-Bold', fontSize=8.5,
            textColor=COLOR_CYAN, spaceAfter=3, spaceBefore=5,
        ),
        'dim': ParagraphStyle(
            'dim', fontName='Courier', fontSize=7.5,
            textColor=COLOR_TEXT_DIM, spaceAfter=4,
        ),
        # ── Flag / statut
        'flag': ParagraphStyle(
            'flag', fontName='Courier-Bold', fontSize=13,
            textColor=COLOR_GREEN, alignment=TA_CENTER,
            spaceBefore=6, spaceAfter=6,
        ),
        'flag_remote': ParagraphStyle(
            'flag_remote', fontName='Courier-Bold', fontSize=13,
            textColor=COLOR_YELLOW, alignment=TA_CENTER,
            spaceBefore=6, spaceAfter=6,
        ),
        'success': ParagraphStyle(
            'success', fontName='Courier-Bold', fontSize=9,
            textColor=COLOR_GREEN, alignment=TA_CENTER,
            spaceBefore=4, spaceAfter=4,
        ),
        'fail': ParagraphStyle(
            'fail', fontName='Courier-Bold', fontSize=9,
            textColor=COLOR_RED, alignment=TA_CENTER,
            spaceBefore=4, spaceAfter=4,
        ),
        'tag': ParagraphStyle(
            'tag', fontName='Courier-Bold', fontSize=7,
            textColor=COLOR_WHITE, alignment=TA_CENTER,
            spaceBefore=2, spaceAfter=2,
        ),
        'section': ParagraphStyle(
            'section', fontName='Courier-Bold', fontSize=11,
            textColor=COLOR_GREEN, spaceBefore=14, spaceAfter=4,
        ),
        'subsection': ParagraphStyle(
            'subsection', fontName='Courier-Bold', fontSize=9.5,
            textColor=COLOR_DARK, spaceBefore=8, spaceAfter=3,
        ),
    }
    return styles, C


# ── Hex dump ──────────────────────────────────────────────────────────────────

def hex_dump(data: bytes, max_bytes: int = 256) -> str:
    data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{i:04x}:  {hex_part:<48}  |{ascii_part}|')
    if len(data) == max_bytes:
        lines.append('         ... (truncated)')
    return '\n'.join(lines)


# ── Table builders ────────────────────────────────────────────────────────────

def make_kv_table(rows, col_widths=None):
    """Tableau clé/valeur — fond blanc, lignes alternées gris clair."""
    if col_widths is None:
        col_widths = [4.5*cm, 12.5*cm]
    t = Table(rows, colWidths=col_widths)
    style = [
        ('FONTNAME',      (0, 0), (0, -1), 'Courier-Bold'),
        ('FONTNAME',      (1, 0), (1, -1), 'Courier'),
        ('FONTSIZE',      (0, 0), (-1, -1), 8.5),
        ('TEXTCOLOR',     (0, 0), (0, -1), COLOR_DARK),
        ('TEXTCOLOR',     (1, 0), (1, -1), COLOR_TEXT),
        ('GRID',          (0, 0), (-1, -1), 0.4, COLOR_GRAY3),
        ('LINEABOVE',     (0, 0), (-1, 0), 1.5, COLOR_GREEN),
        ('LINEBELOW',     (0, -1), (-1, -1), 0.8, COLOR_GRAY2),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 9),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
    ]
    for i in range(len(rows)):
        bg = COLOR_OFF_WHITE if i % 2 == 0 else COLOR_WHITE
        style.append(('BACKGROUND', (0, i), (-1, i), bg))
    t.setStyle(TableStyle(style))
    return t


def make_header_table(rows, col_widths=None):
    """Tableau avec en-tête marine + lignes alternées gris clair."""
    if col_widths is None:
        col_widths = [4*cm, 3.5*cm, 9.5*cm]
    t = Table(rows, colWidths=col_widths)
    style = [
        # En-tête
        ('BACKGROUND',    (0, 0), (-1, 0), COLOR_HDR_BG),
        ('TEXTCOLOR',     (0, 0), (-1, 0), COLOR_GREEN),
        ('FONTNAME',      (0, 0), (-1, 0), 'Courier-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 8.5),
        ('LINEABOVE',     (0, 0), (-1, 0), 1.5, COLOR_GREEN),
        ('LINEBELOW',     (0, 0), (-1, 0), 1, COLOR_GREEN),
        # Données
        ('FONTNAME',      (0, 1), (-1, -1), 'Courier'),
        ('TEXTCOLOR',     (0, 1), (-1, -1), COLOR_TEXT),
        ('GRID',          (0, 0), (-1, -1), 0.4, COLOR_GRAY3),
        ('LINEBELOW',     (0, -1), (-1, -1), 0.8, COLOR_GRAY2),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 9),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
    ]
    for i in range(1, len(rows)):
        bg = COLOR_OFF_WHITE if i % 2 == 1 else COLOR_WHITE
        style.append(('BACKGROUND', (0, i), (-1, i), bg))
    t.setStyle(TableStyle(style))
    return t
