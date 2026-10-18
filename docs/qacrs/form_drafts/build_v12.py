# Fill the official Ibdaa e-judging form (docx) in place: answer boxes, titles, category.
import re, struct, shutil, sys
from xml.sax.saxutils import escape
sys.path.insert(0, '/tmp/claude-0/ibdaa2')
import content as C

import os
U = os.environ.get('U', '/tmp/claude-0/ibdaa2/u')
doc = open(f'{U}/word/document.xml', encoding='utf-8').read()
_F = os.environ.get('FONTNAME', 'Arial')
FONT = f'<w:rFonts w:ascii="{_F}" w:hAnsi="{_F}" w:cs="{_F}"/>'
LATIN = re.compile(r'[A-Za-z]')

def segs(text):
    """split into (text, bold) by **...**"""
    out, bold = [], False
    for i, part in enumerate(text.split('**')):
        if part:
            out.append((part, i % 2 == 1))
    return out

def runs(text, size=22, color=None, bold_all=False):
    xml = []
    for part, bold in segs(text):
        # split Latin-heavy tokens from Arabic so Word lays out mixed text cleanly
        for chunk in re.findall(r'\[\d+\](?:\[\d+\])*|[A-Za-z0-9][A-Za-z0-9 .,:;/_\-–()=+×<>≈%\[\]~@#&?!\'"⁻⁰¹²³⁴⁵⁶⁷⁸⁹]*[A-Za-z0-9)\]%⁻⁰¹²³⁴⁵⁶⁷⁸⁹]|[A-Za-z0-9]|[^A-Za-z0-9\[]+|\[', part):
            latin = bool(re.search(r'[A-Za-z0-9]', chunk))
            rpr = FONT + ('<w:b/><w:bCs/>' if (bold or bold_all) else '') + \
                  (f'<w:color w:val="{color}"/>' if color else '') + \
                  f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>' + ('' if latin else '<w:rtl/>')
            xml.append(f'<w:r><w:rPr>{rpr}</w:rPr><w:t xml:space="preserve">{escape(chunk)}</w:t></w:r>')
    return ''.join(xml)

def para(text, size=22, after=100, jc='both', ind='', bold_all=False, color=None, keep=False):
    ppr = f'{"<w:keepNext/>" if keep else ""}<w:bidi/><w:spacing w:after="{after}" w:line="300" w:lineRule="auto"/>{ind}<w:jc w:val="{jc}"/>'
    return f'<w:p><w:pPr>{ppr}<w:rPr>{FONT}<w:sz w:val="{size}"/><w:szCs w:val="{size}"/><w:rtl/></w:rPr></w:pPr>{runs(text, size, color, bold_all)}</w:p>'

def bullets(items):
    return ''.join(para('–  ' + b, ind='<w:ind w:start="340" w:hanging="340"/>', after=60) for b in items)

def ltr_para(text, size=19, after=50, ind=''):
    return (f'<w:p><w:pPr><w:bidi w:val="0"/><w:spacing w:after="{after}" w:line="276" w:lineRule="auto"/>{ind}<w:jc w:val="left"/></w:pPr>'
            f'<w:r><w:rPr>{FONT}<w:sz w:val="{size}"/><w:szCs w:val="{size}"/></w:rPr><w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>')

def numbered(items):
    out = []
    for i, b in enumerate(items, 1):
        if LATIN.match(b):
            out.append(ltr_para(f'[{i}]  ' + b, ind='<w:ind w:left="520" w:hanging="520"/>'))
        else:
            out.append(para(f'[{i}]  ' + b, size=19, jc='start', ind='<w:ind w:start="520" w:hanging="520"/>', after=50))
    return ''.join(out)

def table(header, rows, widths):
    MAXW = 9300                      # answer cell is 9755 dxa wide; keep nested tables inside it
    if sum(widths) > MAXW:
        f = MAXW / sum(widths); widths = [int(w * f) for w in widths]
    total = sum(widths)
    b = '<w:top w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:left w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:right w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>'
    x = [f'<w:tbl><w:tblPr><w:bidiVisual/><w:tblW w:w="{total}" w:type="dxa"/><w:tblBorders>{b}</w:tblBorders><w:tblLayout w:type="fixed"/>'
         f'<w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:start w:w="80" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:end w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>']
    x += [f'<w:gridCol w:w="{w}"/>' for w in widths]
    x.append('</w:tblGrid>')
    for ri, row in enumerate([header] + rows):
        hdr = ri == 0
        x.append('<w:tr>' + ('<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>' if hdr else '<w:trPr><w:cantSplit/></w:trPr>'))
        for w, cell in zip(widths, row):
            shd = '<w:shd w:val="clear" w:color="auto" w:fill="E8EEF3"/>' if hdr else ''
            x.append(f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{shd}</w:tcPr>'
                     f'{para(cell, size=19, after=0, jc="start", bold_all=hdr)}</w:tc>')
        x.append('</w:tr>')
    x.append('</w:tbl>')
    return ''.join(x) + para('', size=8, after=60)

# ---------------- images
rels = open(f'{U}/word/_rels/document.xml.rels', encoding='utf-8').read()
img_n = [0]
def image(fname, caption):
    img_n[0] += 1
    rid = f'rIdHassanFig{img_n[0]}'
    import os; os.makedirs(f'{U}/word/media', exist_ok=True)
    shutil.copy(f'/tmp/claude-0/ibdaa2/charts/{fname}', f'{U}/word/media/hassan_{fname}')
    global rels
    if rid not in rels:
        rels = rels.replace('</Relationships>', f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/hassan_{fname}"/></Relationships>')
    w, h = struct.unpack('>II', open(f'/tmp/claude-0/ibdaa2/charts/{fname}', 'rb').read()[16:24])
    cx = 5900000; cy = int(cx * h / w)
    pid = 9000 + img_n[0]
    drawing = (f'<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/>'
               f'<wp:docPr id="{pid}" name="Figure {img_n[0]}" descr="{escape(caption)}"/>'
               '<wp:cNvGraphicFramePr><a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" noChangeAspect="1"/></wp:cNvGraphicFramePr>'
               '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
               f'<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="{pid}" name="hassan_{fname}"/><pic:cNvPicPr/></pic:nvPicPr>'
               f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
               f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>'
               '</a:graphicData></a:graphic></wp:inline></w:drawing></w:r>')
    return (f'<w:p><w:pPr><w:keepNext/><w:spacing w:before="80" w:after="20"/><w:jc w:val="center"/></w:pPr>{drawing}</w:p>'
            + para(caption, size=18, jc='center', color='555555', after=120))

def render(items):
    out = []
    for it in items:
        if isinstance(it, str):
            out.append(para(it))
        elif it[0] == 'bullets':
            out.append(bullets(it[1]))
        elif it[0] == 'table':
            out.append(table(it[1], it[2], it[3]))
        elif it[0] == 'caption':
            out.append(para(it[1], size=19, bold_all=True, jc='start', after=40, keep=True))
        elif it[0] == 'ltr':
            out.append(ltr_para(it[1], size=20))
        elif it[0] == 'img':
            out.append(image(it[1], it[2]))
    return ''.join(out)

S9 = render([("caption", "المراجع")]) + numbered(C.REFS) + para('', size=8) + render(C.S9_AI)
bodies = [render(s) for s in C.SECTIONS[:8]] + [S9]

# ---------------- replace the 9 answer boxes (cells that hold the placeholder)
def replace_cell_containing(xml, marker, new_paras, start=0):
    i = xml.index(marker, start)
    s = max(xml.rfind('<w:tc>', 0, i), xml.rfind('<w:tc ', 0, i))
    tcpr_end = xml.index('</w:tcPr>', s) + len('</w:tcPr>')
    e = xml.index('</w:tc>', i)
    # make sure no nested cell between s and i
    assert xml.count('<w:tc>', s + 5, i) == 0
    return xml[:tcpr_end] + new_paras + xml[e:], tcpr_end + len(new_paras)

pos = 0
for body in bodies:
    doc, pos = replace_cell_containing(doc, 'إجابتك', body, pos)
assert 'إجابتك' not in doc and 'Write your answer' not in doc

# ---------------- title and category cells (the cell right after each label cell)
def fill_next_cell(xml, label, text, ltr=False):
    i = xml.index(label)
    e = xml.index('</w:tc>', i)
    s = xml.index('<w:tc>', e)
    tcpr_end = xml.index('</w:tcPr>', s) + len('</w:tcPr>')
    ce = xml.index('</w:tc>', s)
    if ltr:
        p = (f'<w:p><w:pPr><w:spacing w:after="0"/><w:jc w:val="left"/></w:pPr><w:r><w:rPr>{FONT}<w:b/><w:bCs/><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr>'
             f'<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>')
    else:
        p = para(text, after=0, jc='start', bold_all=True)
    return xml[:tcpr_end] + p + xml[ce:]

doc = doc.replace('<w:t>100 – 300 words</w:t>', '<w:t>80 – 400 words</w:t>', 1)  # latest official limit
doc = fill_next_cell(doc, 'Project title in Arabic', C.TITLE_AR)
doc = fill_next_cell(doc, 'Project title in English', C.TITLE_EN, ltr=True)
doc = fill_next_cell(doc, 'Main category', C.MAIN_CAT)
doc = fill_next_cell(doc, 'Subcategory', C.SUB_CAT)


# drop the template's trailing empty section (it only adds a blank page); keep the real section settings
import re as _re
_m = _re.search(r'(<w:sectPr w:rsidR="00B35B02".*?</w:sectPr>)', doc, _re.S)
if _m:
    _sect = _m.group(1)
    _tail = doc.rfind('<w:p w:rsidR="00D264DE" w:rsidRDefault="00D264DE"/><w:sectPr')
    if _tail > 0:
        doc = doc.replace(_sect, '', 1)
        _tail = doc.rfind('<w:p w:rsidR="00D264DE" w:rsidRDefault="00D264DE"/><w:sectPr')
        doc = doc[:_tail] + _sect + '</w:body></w:document>'

open(f'{U}/word/document.xml', 'w', encoding='utf-8').write(doc)
open(f'{U}/word/_rels/document.xml.rels', 'w', encoding='utf-8').write(rels)
print('ok', len(doc))
