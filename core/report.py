"""
Penterous — PDF report generator (ultra-professional hacker design).
by p3nt2r0us
"""
import os
import datetime
from typing import Optional

from utils.logger import info, success, warning, error


def _esc(text: str) -> str:
    """Échappe les caractères spéciaux XML pour ReportLab Paragraph."""
    return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;'))


try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm, mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, Preformatted, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER
    from templates.report_template import (
        build_styles, hex_dump,
        make_kv_table, make_header_table,
        AsciiArtBox, GlowLine, FlagBox, SkullBadge, HackerPageTemplate,
        COLOR_DARK, COLOR_DARK2, COLOR_DARK3, COLOR_DARK4,
        COLOR_GREEN, COLOR_GREEN2, COLOR_GREEN3,
        COLOR_CYAN, COLOR_CYAN2, COLOR_BLUE,
        COLOR_YELLOW, COLOR_ORANGE, COLOR_RED,
        COLOR_WHITE, COLOR_GRAY, COLOR_GRAY2, COLOR_GRAY3,
    )
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False



class ReportGenerator:
    def __init__(self, output_dir: str = './reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, binary_report, exploit_result, output_path: str = None) -> Optional[str]:
        if not REPORTLAB_OK:
            warning("reportlab non installé — PDF ignoré. Lancer : pip install reportlab")
            return None

        if output_path is None:
            binary_name = os.path.basename(binary_report.path)
            date_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            flag_tag = ""
            if exploit_result.remote_flag:
                flag_tag = "_REMOTE"
            elif exploit_result.flag:
                flag_tag = "_PWNED"
            elif exploit_result.success:
                flag_tag = "_SHELL"
            filename = f"{binary_name}_penterous_{date_str}{flag_tag}.pdf"
            output_path = os.path.join(self.output_dir, filename)

        try:
            self._build_pdf(binary_report, exploit_result, output_path)
            success(f"PDF report saved: {output_path}")
            return output_path
        except Exception as e:
            error(f"PDF generation failed: {e}")
            import traceback; traceback.print_exc()
            return None

    def generate_text_report(self, binary_report, exploit_result) -> str:
        """Rapport texte de secours si PDF désactivé."""
        lines = [
            "=" * 60,
            "  PENTEROUS — EXPLOIT REPORT",
            "=" * 60,
            f"  Binary   : {binary_report.path}",
            f"  Arch     : {binary_report.arch} {binary_report.bits}-bit",
            f"  Strategy : {exploit_result.strategy_used}",
            f"  Status   : {'PWNED' if exploit_result.success else 'FAILED'}",
        ]
        if exploit_result.flag:
            lines.append(f"  Flag     : {exploit_result.flag}")
        if exploit_result.remote_flag:
            lines.append(f"  RemoteFlag: {exploit_result.remote_flag}")
        lines.append("=" * 60)
        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────
    def _build_pdf(self, br, er, path: str):
        styles, C = build_styles()
        binary_name = os.path.basename(br.path)

        page_cb = HackerPageTemplate(binary_name)

        doc = SimpleDocTemplate(
            path, pagesize=A4,
            leftMargin=1.9*cm, rightMargin=1.9*cm,
            topMargin=1.5*cm, bottomMargin=1.4*cm,
            title="Penterous Exploit Report",
            author="p3nt2r0us",
        )

        story = []
        now = datetime.datetime.now().strftime('%Y-%m-%d  %H:%M:%S')
        pwned = er.success

        # ── COUVERTURE ────────────────────────────────────────────────────────
        story += self._section_cover(C, br, er, now, pwned)
        story.append(PageBreak())

        # ── SOMMAIRE ──────────────────────────────────────────────────────────
        story += self._section_toc(C, er)
        story.append(PageBreak())

        # ── 1. ANALYSE STATIQUE ───────────────────────────────────────────────
        story += self._section_static(C, br)
        story.append(PageBreak())

        # ── 2. EXPLOITATION ───────────────────────────────────────────────────
        story += self._section_exploitation(C, br, er)

        # ── 3. SCRIPT D'EXPLOIT ───────────────────────────────────────────────
        if er.exploit_script:
            story.append(PageBreak())
            story += self._section_exploit_script(C, er)

        # ── 4. REMÉDIATION ────────────────────────────────────────────────────
        story.append(PageBreak())
        story += self._section_remediation(C, br, er)

        # ── 5. RESSOURCES ─────────────────────────────────────────────────────
        story += self._section_resources(C, er)

        # ── PIED DE PAGE FINAL ────────────────────────────────────────────────
        story.append(Spacer(1, 0.8*cm))
        story.append(GlowLine(color=COLOR_CYAN, thickness=0.8))
        story.append(Spacer(1, 0.15*cm))
        story.append(Paragraph(
            "PENTEROUS  ·  BINARY EXPLOITATION FRAMEWORK  ·  EDUCATIONAL USE ONLY  ·  by p3nt2r0us",
            C['dim']
        ))

        doc.build(story, onFirstPage=page_cb, onLaterPages=page_cb)

    # ── HELPER : EN-TÊTE DE SECTION ───────────────────────────────────────────
    def _sec_header(self, C, number: str, title: str):
        s = []
        s.append(Spacer(1, 0.2*cm))
        label = f"  [{number}]  {title}"
        t = Table([[label]], colWidths=[17*cm])
        t.setStyle(TableStyle([
            # fond marine profond, texte néon vert
            ('BACKGROUND',    (0, 0), (-1, -1), COLOR_DARK),
            ('TEXTCOLOR',     (0, 0), (-1, -1), COLOR_GREEN),
            ('FONTNAME',      (0, 0), (-1, -1), 'Courier-Bold'),
            ('FONTSIZE',      (0, 0), (-1, -1), 11),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING',   (0, 0), (-1, -1), 10),
            # liseré vert 3px en haut, liseré fin en bas
            ('LINEABOVE',     (0, 0), (-1, 0), 3, COLOR_GREEN),
            ('LINEBELOW',     (0, 0), (-1, 0), 0.5, COLOR_CYAN),
        ]))
        s.append(t)
        s.append(Spacer(1, 0.3*cm))
        return s

    # ── COUVERTURE ────────────────────────────────────────────────────────────
    def _section_cover(self, C, br, er, now, pwned):
        s = []

        # ── Titre propre PENTEROUS ────────────────────────────────────────
        s.append(Spacer(1, 1.2*cm))
        s.append(Paragraph("PENTEROUS", C['title_main']))
        s.append(Spacer(1, 0.1*cm))
        s.append(Paragraph("Binary Exploitation Framework", C['title_sub']))
        s.append(Paragraph("Automated CTF Exploit Report  ·  by p3nt2r0us", C['subtitle']))

        # Badge statut
        s.append(Spacer(1, 0.2*cm))
        s.append(SkullBadge(pwned=pwned))
        s.append(Spacer(1, 0.35*cm))

        # Ligne néon
        s.append(GlowLine(color=COLOR_CYAN, thickness=1.5, glow_color=COLOR_DARK3))
        s.append(Spacer(1, 0.35*cm))

        # Tableau récapitulatif
        mode_display = er.mode.upper()
        if er.remote_host:
            mode_display += f"  -  {er.remote_host}:{er.remote_port}"

        rows = [
            ["BINARY",       os.path.basename(br.path)],
            ["FULL PATH",    br.path],
            ["ARCHITECTURE", f"{br.arch}  ·  {br.bits}-bit"],
            ["DATE",         now],
            ["STRATEGY",     er.strategy_used.upper()],
            ["MODE",         mode_display],
            ["OFFSET",       f"{er.offset} bytes"],
            ["DURATION",     f"{er.duration:.2f} s"],
            ["STATUS",       "PWNED" if pwned else "FAILED"],
        ]
        if er.remote_host:
            rows.append(["REMOTE TARGET", f"{er.remote_host}:{er.remote_port}"])

        s.append(make_kv_table(rows))
        s.append(Spacer(1, 0.45*cm))

        # Bannière flag
        display_flag = er.remote_flag or er.flag
        if display_flag:
            s.append(GlowLine(color=COLOR_GREEN, thickness=1.2, glow_color=COLOR_DARK3))
            s.append(Spacer(1, 0.25*cm))
            is_remote = bool(er.remote_flag)
            s.append(FlagBox(flag_text=display_flag, is_remote=is_remote))
            if er.remote_flag and er.flag and er.flag != er.remote_flag:
                s.append(Spacer(1, 0.15*cm))
                s.append(Paragraph(f"Local flag : {_esc(er.flag)}", C['body_dim']))
            s.append(Spacer(1, 0.25*cm))
            s.append(GlowLine(color=COLOR_GREEN, thickness=1.2, glow_color=COLOR_DARK3))

        s.append(Spacer(1, 0.45*cm))
        return s

    # ── SOMMAIRE ──────────────────────────────────────────────────────────────
    def _section_toc(self, C, er):
        s = []
        s += self._sec_header(C, "00", "SOMMAIRE")

        sections = [
            ("01", "Analyse statique",           "Protections, fonctions vulnérables, chaînes d'intérêt"),
            ("02", "Exploitation",               "Stratégie, offset, payload, flag capturé"),
            ("03", "Script d'exploit",           "Script pwntools prêt à l'emploi"),
            ("04", "Remédiation",                "Recommandations de sécurité et corrections"),
            ("05", "Ressources",                 "Références et plateformes d'apprentissage"),
        ]

        toc_rows = [["#", "SECTION", "CONTENU"]]
        for num, name, desc in sections:
            toc_rows.append([f"[{num}]", name, desc])

        t = make_header_table(toc_rows, col_widths=[1.5*cm, 4.5*cm, 11*cm])
        s.append(t)
        s.append(Spacer(1, 0.4*cm))

        # Note d'intro
        s.append(GlowLine(color=COLOR_CYAN, thickness=0.8))
        s.append(Spacer(1, 0.2*cm))
        s.append(Paragraph(
            "Ce rapport a été généré automatiquement par Penterous après exploitation réussie du binaire cible. "
            "Il détaille les protections détectées, la stratégie utilisée, le payload injecté et fournit un "
            "script d'exploit reproductible ainsi que des recommandations de remédiation.",
            C['body']
        ))
        s.append(Spacer(1, 0.15*cm))
        s.append(Paragraph(
            "Usage éducatif uniquement — ne pas utiliser sur des systèmes sans autorisation explicite.",
            C['body_dim']
        ))
        return s

    # ── ANALYSE STATIQUE ──────────────────────────────────────────────────────
    def _section_static(self, C, br):
        s = []
        s += self._sec_header(C, "01", "ANALYSE STATIQUE")

        # Tableau des protections
        prot_map = [
            ("NX / DEP",     br.protections.get("NX", False),             "Shellcode impossible — ROP requis",        True),
            ("Stack Canary",  br.protections.get("Canary", False),         "BOF bloqué — fuite du canary nécessaire",  False),
            ("ASLR",          br.protections.get("ASLR", False),           "Adresses libc aléatoires — fuite requise", False),
            ("PIE",           br.protections.get("PIE", False),            "Adresses binaire aléatoires",              False),
            ("Full RELRO",    br.protections.get("RELRO", False) == "Full","Écrasement GOT bloqué",                    True),
            ("FORTIFY",       br.protections.get("FORTIFY", False),        "Fonctions dangereuses limitées",           True),
        ]

        header = [["PROTECTION", "STATUT", "IMPACT SÉCURITÉ"]]
        rows = []
        for name, enabled, impact, _ in prot_map:
            status = "ACTIVÉ" if enabled else "DÉSACTIVÉ"
            rows.append([name, status, impact])

        t = make_header_table(header + rows, col_widths=[4*cm, 3.2*cm, 9.8*cm])
        for i, (name, enabled, _, good_when_on) in enumerate(prot_map, start=1):
            if good_when_on:
                cell_color = COLOR_RED if not enabled else COLOR_GREEN3
            else:
                cell_color = COLOR_GREEN3 if not enabled else COLOR_YELLOW
            t.setStyle(TableStyle([
                ('TEXTCOLOR', (1, i), (1, i), cell_color),
                ('FONTNAME',  (1, i), (1, i), 'Courier-Bold'),
            ]))
        s.append(t)
        s.append(Spacer(1, 0.45*cm))

        # Fonctions vulnérables
        if br.vuln_functions:
            s.append(Paragraph("[ FONCTIONS VULNÉRABLES ]", C['label']))
            s.append(Spacer(1, 0.1*cm))
            for vf in br.vuln_functions:
                s.append(Paragraph(f"  &gt;  {_esc(str(vf))}", C['code']))
            s.append(Spacer(1, 0.2*cm))

        # Win functions
        if br.win_functions:
            s.append(Paragraph("[ FONCTIONS WIN / CIBLE ]", C['label']))
            s.append(Spacer(1, 0.1*cm))
            for name, addr in br.win_functions:
                s.append(Paragraph(f"  &gt;  {_esc(name)}()  à  0x{addr:x}", C['code']))
            s.append(Spacer(1, 0.2*cm))

        # Chaînes intéressantes
        if getattr(br, 'interesting_strings', None):
            s.append(Paragraph("[ CHAÎNES D'INTÉRÊT ]", C['label']))
            s.append(Spacer(1, 0.1*cm))
            for st in br.interesting_strings[:10]:
                s.append(Paragraph(f"  {_esc(repr(st))}", C['code']))
            s.append(Spacer(1, 0.2*cm))

        # Stratégies recommandées
        if getattr(br, 'recommended_strategies', None):
            s.append(Paragraph("[ STRATÉGIES RECOMMANDÉES ]", C['label']))
            s.append(Spacer(1, 0.1*cm))
            rows2 = [["#", "STRATÉGIE", "CONFIANCE"]]
            for i, (strat, conf) in enumerate(br.recommended_strategies, 1):
                rows2.append([str(i), strat, f"{int(conf*100)} %"])
            t2 = make_header_table(rows2, col_widths=[0.8*cm, 9*cm, 3.2*cm])
            s.append(t2)

        return s

    # ── EXPLOITATION ──────────────────────────────────────────────────────────
    def _section_exploitation(self, C, br, er):
        s = []
        s += self._sec_header(C, "02", "EXPLOITATION")

        # Tableau récapitulatif
        rows = [
            ["STRATÉGIE",  er.strategy_used.upper()],
            ["OFFSET",     f"{er.offset} bytes"],
            ["MODE",       er.mode.upper()],
            ["RÉSULTAT",   "SUCCESS" if er.success else "FAILED"],
        ]
        if er.libc_base:
            rows.append(["LIBC BASE", f"0x{er.libc_base:x}"])
        if er.remote_host:
            rows.append(["REMOTE", f"{er.remote_host}:{er.remote_port}"])
        s.append(make_kv_table(rows))
        s.append(Spacer(1, 0.4*cm))

        # Hex dump du payload
        if er.payload:
            s.append(Paragraph("[ PAYLOAD — HEX DUMP ]", C['label']))
            s.append(Spacer(1, 0.1*cm))
            dump = hex_dump(er.payload, max_bytes=256)
            s.append(Preformatted(dump, C['code']))
            s.append(Spacer(1, 0.3*cm))

        # Flag local
        if er.flag and not er.remote_flag:
            s.append(Spacer(1, 0.15*cm))
            s.append(FlagBox(flag_text=er.flag, is_remote=False))

        # Flag remote
        if er.remote_flag:
            s.append(Spacer(1, 0.25*cm))
            s.append(FlagBox(flag_text=er.remote_flag, is_remote=True))
            if er.flag and er.flag != er.remote_flag:
                s.append(Spacer(1, 0.1*cm))
                s.append(Paragraph(f"[ Local flag : {_esc(er.flag)} ]", C['body_dim']))

        return s

    # ── SCRIPT D'EXPLOIT ──────────────────────────────────────────────────────
    def _section_exploit_script(self, C, er):
        s = []
        s += self._sec_header(C, "03", "SCRIPT D'EXPLOIT")
        s.append(Paragraph(
            "Script pwntools généré automatiquement par Penterous. "
            "Adapter la section remote et le chemin libc selon l'environnement cible.",
            C['body']
        ))
        s.append(Spacer(1, 0.35*cm))
        s.append(GlowLine(color=COLOR_CYAN, thickness=1.2))
        s.append(Spacer(1, 0.1*cm))
        s.append(Preformatted(er.exploit_script, C['code_script']))
        s.append(Spacer(1, 0.1*cm))
        s.append(GlowLine(color=COLOR_CYAN, thickness=1.2))
        s.append(Spacer(1, 0.3*cm))
        return s

    # ── REMÉDIATION ───────────────────────────────────────────────────────────
    def _section_remediation(self, C, br, er):
        s = []
        s += self._sec_header(C, "04", "RECOMMANDATIONS DE REMÉDIATION")

        recs = self._get_remediation(br, er)
        for i, rec in enumerate(recs, 1):
            s.append(Paragraph(f"  {i:02d}.  {_esc(rec)}", C['body']))
            s.append(Spacer(1, 0.05*cm))

        return s

    # ── RESSOURCES ────────────────────────────────────────────────────────────
    def _section_resources(self, C, er):
        s = []
        s.append(Spacer(1, 0.3*cm))
        s += self._sec_header(C, "05", "RESSOURCES D'APPRENTISSAGE")

        resources = self._get_resources(er.strategy_used)
        rows = [["#", "RESSOURCE"]]
        for i, res in enumerate(resources, 1):
            rows.append([str(i), _esc(res)])
        t = make_header_table(rows, col_widths=[0.8*cm, 16.2*cm])
        s.append(t)

        return s

    # ── DONNÉES DE REMÉDIATION ────────────────────────────────────────────────
    def _get_remediation(self, br, er) -> list:
        recs = []
        prot = br.protections

        if not prot.get("NX", False):
            recs.append("Activer NX/DEP : compiler avec -z noexecstack (ou bit NX matériel actif)")
        if not prot.get("Canary", False):
            recs.append("Activer les canaries de pile : compiler avec -fstack-protector-strong")
        if not prot.get("ASLR", False):
            recs.append("Activer ASLR : echo 2 > /proc/sys/kernel/randomize_va_space")
        if not prot.get("PIE", False):
            recs.append("Activer PIE : compiler avec -fpie -pie")
        if prot.get("RELRO", False) != "Full":
            recs.append("Activer Full RELRO : compiler avec -Wl,-z,relro,-z,now")

        strat = er.strategy_used.lower()
        if strat == 'ret2win':
            recs.append("Supprimer ou stripper les fonctions helper win()/get_flag() des binaires de production")
            recs.append("Contrôler les bornes de toutes les entrées utilisateur : utiliser fgets() avec limite explicite plutôt que gets()/scanf('%s')")
        if strat in ('ret2libc', 'leak_ret2libc'):
            recs.append("Combiner canaries de pile + ASLR pour contrer les attaques ret2libc")
        if strat == 'format_string':
            recs.append("Ne jamais passer une entrée utilisateur directement à printf/fprintf/sprintf : toujours utiliser printf('%s', user_input)")
        if strat == 'ret2shellcode':
            recs.append("Activer le bit NX (pile non exécutable) — l'injection de shellcode nécessite une pile/heap exécutable")

        if not recs:
            recs.append("Appliquer les flags de durcissement modernes : -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fpie -pie -z relro -z now")
            recs.append("Mettre à jour régulièrement la libc et les bibliothèques système")

        recs.append("Réaliser des audits de sécurité réguliers et des revues de durcissement des binaires")
        recs.append("Utiliser AddressSanitizer (ASan) et UndefinedBehaviorSanitizer (UBSan) lors du développement")
        return recs

    # ── DONNÉES DE RESSOURCES ────────────────────────────────────────────────
    def _get_resources(self, strategy: str) -> list:
        common = [
            "pwn.college — plateforme d'apprentissage structurée (pwn.college)",
            "pwntools documentation — pwntools.readthedocs.io",
            "LiveOverflow YouTube — playlist Binary Exploitation",
            "CTFtime.org — compétitions CTF passées et à venir",
            "exploit.education — VMs de pratique pwn (exploit.education)",
        ]
        strat_resources = {
            'ret2win': [
                "ret2win technique — walkthrough ir0nstone gitbook",
                "Smashing the Stack for Fun and Profit — Aleph One (phrack.org/issues/49)",
            ],
            'ret2libc': [
                "ret2libc technique — ir0nstone.gitbook.io",
                "ROP Emporium — ropemporium.com (pratiquer le return-oriented programming)",
            ],
            'leak_ret2libc': [
                "GOT/PLT leak technique — ctf101.org/binary-exploitation/return-to-libc",
                "pwntools Leak guide — pwntools.readthedocs.io/en/stable/rop.html",
            ],
            'format_string': [
                "Format String Exploitation — exploit.education/format-string",
                "OWASP Format String — owasp.org/www-community/attacks/Format_string_attack",
            ],
            'rop_chain': [
                "ROP Emporium — ropemporium.com",
                "Introduction to ROP — ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming",
            ],
            'ret2shellcode': [
                "Shellcode techniques — shell-storm.org/shellcode",
                "Shellcoding for Linux/x86 — exploit-db.com",
            ],
            'srop': [
                "SROP explained — phrack.org/issues/69/3.html",
                "SigReturn-Oriented Programming — ctf wiki",
            ],
        }
        return strat_resources.get(strategy.lower(), []) + common
