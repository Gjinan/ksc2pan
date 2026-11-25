#!/usr/bin/env python3
"""把本项目的 Markdown 报告转成排版好的 Word（.docx）。

只支持本项目用到的 Markdown 子集：标题/段落/无序·有序列表/表格/代码块/引用/分隔线。
依赖 python-docx（pip install python-docx）。

用法：
  python tools/md2docx.py --src ../output/KSC2PAN_实施报告.md --dst ../output/KSC2PAN_实施报告.docx
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

SANS = "微软雅黑"
SERIF = "宋体"
MONO = "Consolas"
ACCENT = RGBColor(0x1F, 0x3A, 0x5F)
MUTED = RGBColor(0x59, 0x59, 0x59)


# ------------------------------------------------------------------ 基础工具
def set_east_asia(run_or_style, font_name: str) -> None:
    rpr = run_or_style._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:eastAsia"), font_name)
    rfonts.set(qn("w:ascii"), font_name)
    rfonts.set(qn("w:hAnsi"), font_name)


def shade(element, color: str) -> None:
    ppr = element.get_or_add_pPr() if hasattr(element, "get_or_add_pPr") else element
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), color)
    ppr.append(shd)


def cell_shade(cell, color: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), color)
    tc_pr.append(shd)


def add_field(paragraph, instr: str) -> None:
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), instr)
    run = OxmlElement("w:r")
    text = OxmlElement("w:t")
    text.text = " "
    run.append(text)
    fld.append(run)
    paragraph._p.append(fld)


def bottom_border(paragraph, color: str = "D0D7E2") -> None:
    ppr = paragraph._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "6")
    bottom.set(qn("w:space"), "1")
    bottom.set(qn("w:color"), color)
    borders.append(bottom)
    ppr.append(borders)


# ------------------------------------------------------------------ 行内格式
INLINE_RE = re.compile(r"(\*\*.+?\*\*|`[^`]+`)")


def add_inline(paragraph, text: str, size: float = 10.5, color=None) -> None:
    for token in INLINE_RE.split(text):
        if not token:
            continue
        if token.startswith("**") and token.endswith("**"):
            run = paragraph.add_run(token[2:-2])
            run.bold = True
            run.font.size = Pt(size)
        elif token.startswith("`") and token.endswith("`"):
            run = paragraph.add_run(token[1:-1])
            run.font.name = MONO
            set_east_asia(run, MONO)
            run.font.size = Pt(max(8.0, size - 1.2))
            run.font.color.rgb = RGBColor(0xA3, 0x2D, 0x2D)
        else:
            run = paragraph.add_run(token)
            run.font.size = Pt(size)
        if color is not None:
            run.font.color.rgb = color


# ------------------------------------------------------------------ 文档骨架
def build_styles(doc: Document) -> None:
    normal = doc.styles["Normal"]
    normal.font.name = SERIF
    normal.font.size = Pt(10.5)
    set_east_asia(normal, SERIF)
    normal.paragraph_format.line_spacing = 1.45
    normal.paragraph_format.space_after = Pt(4)

    specs = {"Heading 1": 16, "Heading 2": 13.5, "Heading 3": 12, "Heading 4": 11}
    for name, size in specs.items():
        style = doc.styles[name]
        style.font.name = SANS
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = ACCENT
        set_east_asia(style, SANS)
        style.paragraph_format.space_before = Pt(14 if name == "Heading 1" else 10)
        style.paragraph_format.space_after = Pt(6)
        style.paragraph_format.keep_with_next = True


def setup_page(doc: Document, title: str) -> None:
    section = doc.sections[0]
    section.page_width = Cm(21.0)
    section.page_height = Cm(29.7)
    section.top_margin = Cm(2.2)
    section.bottom_margin = Cm(2.0)
    section.left_margin = Cm(2.2)
    section.right_margin = Cm(2.2)

    header_p = section.header.paragraphs[0]
    header_p.text = title
    header_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    for run in header_p.runs:
        run.font.size = Pt(8)
        run.font.name = SANS
        set_east_asia(run, SANS)
        run.font.color.rgb = MUTED
    bottom_border(header_p)

    footer_p = section.footer.paragraphs[0]
    footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer_p.add_run("第 ")
    run.font.size = Pt(8)
    add_field(footer_p, "PAGE")
    run = footer_p.add_run(" 页")
    run.font.size = Pt(8)

    settings = doc.settings.element
    update = OxmlElement("w:updateFields")
    update.set(qn("w:val"), "true")
    settings.append(update)


def add_cover(doc: Document, title: str, subtitle: str, meta: list[list[str]]) -> None:
    for _ in range(3):
        doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(title)
    run.font.name = SANS
    set_east_asia(run, SANS)
    run.font.size = Pt(26)
    run.bold = True
    run.font.color.rgb = ACCENT

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(subtitle)
    run.font.name = SANS
    set_east_asia(run, SANS)
    run.font.size = Pt(14)
    run.font.color.rgb = MUTED

    for _ in range(2):
        doc.add_paragraph()

    if meta:
        table = doc.add_table(rows=0, cols=2)
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for key, value in meta:
            cells = table.add_row().cells
            cells[0].width = Cm(4.2)
            cells[1].width = Cm(11.0)
            cell_shade(cells[0], "F2F5FA")
            for idx, text in enumerate((key, value)):
                para = cells[idx].paragraphs[0]
                run = para.add_run(text)
                run.font.size = Pt(10)
                run.font.name = SANS
                set_east_asia(run, SANS)
                run.bold = idx == 0

    doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("内部资料 · 请勿外传")
    run.font.size = Pt(9)
    run.font.color.rgb = MUTED

    doc.add_page_break()


def add_toc(doc: Document) -> None:
    p = doc.add_paragraph()
    run = p.add_run("目  录")
    run.font.name = SANS
    set_east_asia(run, SANS)
    run.font.size = Pt(16)
    run.bold = True
    run.font.color.rgb = ACCENT
    p.paragraph_format.space_after = Pt(10)

    para = doc.add_paragraph()
    add_field(para, 'TOC \\o "1-2" \\h \\z \\u')
    doc.add_page_break()


# ------------------------------------------------------------------ 内容渲染
def add_code_block(doc: Document, lines: list[str]) -> None:
    for i, line in enumerate(lines):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.0
        p.paragraph_format.left_indent = Cm(0.3)
        p.paragraph_format.right_indent = Cm(0.1)
        shade(p._p, "F5F6F8")
        run = p.add_run(line if line else " ")
        run.font.name = MONO
        set_east_asia(run, SERIF)
        run.font.size = Pt(8.5)
        run.font.color.rgb = RGBColor(0x2C, 0x2C, 0x2A)
        if i == len(lines) - 1:
            p.paragraph_format.space_after = Pt(8)


def add_table(doc: Document, rows: list[list[str]]) -> None:
    if not rows:
        return
    header, body = rows[0], rows[1:]
    cols = max(len(r) for r in rows)
    table = doc.add_table(rows=1, cols=cols)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True

    for idx in range(cols):
        cell = table.rows[0].cells[idx]
        cell_shade(cell, "E8EEF7")
        para = cell.paragraphs[0]
        para.paragraph_format.space_after = Pt(0)
        add_inline(para, header[idx] if idx < len(header) else "", size=9)
        for run in para.runs:
            run.bold = True
            run.font.color.rgb = ACCENT

    for row in body:
        cells = table.add_row().cells
        for idx in range(cols):
            para = cells[idx].paragraphs[0]
            para.paragraph_format.space_after = Pt(0)
            para.paragraph_format.line_spacing = 1.15
            add_inline(para, row[idx] if idx < len(row) else "", size=9)
    for row in table.rows:
        tr_pr = row._tr.get_or_add_trPr()
        cant = OxmlElement("w:cantSplit")
        tr_pr.append(cant)
    header_tr = table.rows[0]._tr
    tr_pr = header_tr.get_or_add_trPr()
    repeat = OxmlElement("w:tblHeader")
    tr_pr.append(repeat)

    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def render(src: Path, dst: Path) -> None:
    lines = src.read_text(encoding="utf-8").splitlines()

    title = lines[0].lstrip("# ").strip()
    subtitle = ""
    meta: list[list[str]] = []
    for line in lines[1:8]:
        if line.startswith("## "):
            subtitle = line[3:].strip()
            break

    # 抽取文首的元信息表
    for line in lines:
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) == 2 and not set(cells[0]) <= set("-: "):
                meta.append(cells)
        elif meta and not line.startswith("|"):
            break

    doc = Document()
    build_styles(doc)
    setup_page(doc, f"{title} · V1.0")
    add_cover(doc, title, subtitle, meta)
    add_toc(doc)

    i = 0
    subtitle_done = False
    meta_skipped = not meta
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("```"):
            i += 1
            block: list[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i].rstrip())
                i += 1
            i += 1
            add_code_block(doc, block)
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                    rows.append(cells)
                i += 1
            if not meta_skipped and rows == meta:
                meta_skipped = True
                continue
            add_table(doc, rows)
            continue

        if stripped.startswith("#"):
            level = len(stripped) - len(stripped.lstrip("#"))
            text = stripped[level:].strip()
            if level == 1 and text == title:
                i += 1
                continue
            if level == 2 and text == subtitle and not subtitle_done:
                subtitle_done = True
                i += 1
                continue
            doc.add_heading(text, level=min(level, 4))
            i += 1
            continue

        if stripped in ("---", "***", "___"):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(6)
            bottom_border(p)
            i += 1
            continue

        if stripped.startswith(">"):
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Cm(0.6)
            add_inline(p, stripped.lstrip("> ").strip(), size=10, color=MUTED)
            i += 1
            continue

        m_bullet = re.match(r"^(\s*)[-*]\s+(.*)$", line)
        if m_bullet:
            indent = len(m_bullet.group(1))
            style = "List Bullet 2" if indent >= 2 else "List Bullet"
            p = doc.add_paragraph(style=style)
            p.paragraph_format.space_after = Pt(2)
            add_inline(p, m_bullet.group(2))
            i += 1
            continue

        m_num = re.match(r"^(\s*)\d+[.)]\s+(.*)$", line)
        if m_num:
            indent = len(m_num.group(1))
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Cm(0.75 + 0.6 * (indent // 2))
            p.paragraph_format.first_line_indent = Cm(-0.45)
            p.paragraph_format.space_after = Pt(2)
            add_inline(p, m_num.group(0).strip())
            i += 1
            continue

        if not stripped:
            i += 1
            continue

        p = doc.add_paragraph()
        add_inline(p, stripped)
        i += 1

    dst.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(dst))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--dst", required=True)
    args = ap.parse_args()
    render(Path(args.src), Path(args.dst))
    print(f"已生成：{args.dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
