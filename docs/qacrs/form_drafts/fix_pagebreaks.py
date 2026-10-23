# Post-process the built form: a section that exactly fills its page used to leave a blank page,
# because the template puts an empty spacer paragraph + a manual page-break paragraph after each
# answer table. Replace that pair with pageBreakBefore on the next table's first paragraph.
import re, sys
p = sys.argv[1]; x = open(p, encoding="utf-8").read()
spacer = r'<w:p [^>]*><w:pPr><w:spacing w:after="200"/><w:rPr>(?:(?!</w:p>).)*?</w:rPr></w:pPr></w:p>'
brk = r'<w:p [^>]*>(?:(?!</w:p>).)*?<w:br w:type="page"/></w:r></w:p>'
pat = re.compile(r'</w:tbl>(?:' + spacer + r')?' + brk + r'(<w:tbl>.*?<w:p [^>]*>)(<w:pPr>)?', re.S)
def rep(m):
    head = m.group(1)
    return '</w:tbl>' + head + '<w:pPr><w:pageBreakBefore/>' if m.group(2) else '</w:tbl>' + head + '<w:pPr><w:pageBreakBefore/></w:pPr>'
x2, n = pat.subn(rep, x)
open(p, "w", encoding="utf-8").write(x2); print("page breaks converted:", n)
