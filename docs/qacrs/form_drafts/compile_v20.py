"""Compile content_v20_src.py -> content_v20.py: number [@key] citations by first appearance, build REFS in that order."""
import re, runpy, pprint, sys
src = runpy.run_path('content_v20_src.py')
old = runpy.run_path('content_v19.py')['REFS']
keys = ['nao','neprash','cs26','ecc','doe','shamoon','triton','anwar','nespoli','islam','defender','cspatent','shameli','bozor',
        'lucas','glover','farhi','sha','z3','highs','cyborg','zta','cogburn','cvar','cvss','pwc','dfir','attackflow','cisa','attack',
        'mldsa','sdaia','cicids','claude','openai']
R = dict(zip(keys, old))
R['hammar'] = ('Hammar, K., & Stadler, R. (2022). Intrusion Prevention Through Optimal Stopping. IEEE Transactions on Network and '
               'Service Management, 19(3). https://doi.org/10.1109/TNSM.2022.3176781')
R['nusuk'] = ('Ministry of Hajj and Umrah. (2025, September 19). Ministry of Hajj and Umrah: 30 million users of the Nusuk application '
              'from 190 countries around the world [News release]. https://haj.gov.sa/en/Media-Center/Ministry-News/'
              'Ministry-of-Hajj-and-Umrah-30-million-users-of-the-Nusuk-application-from-190-countries-around-the-w')
order = ["S1","S2","S3","S4","S5","S6","S7","S8","S9_AI"]
seen = []
def walk(x, f):
    if isinstance(x, str): return f(x)
    if isinstance(x, tuple): return tuple(walk(y, f) for y in x)
    if isinstance(x, list): return [walk(y, f) for y in x]
    return x
def collect(t):
    for k in re.findall(r'\[@(\w+)\]', t):
        assert k in R, k
        if k not in seen: seen.append(k)
    return t
for k in order: walk(src[k], collect)
num = {k: i + 1 for i, k in enumerate(seen)}
out_d = {k: walk(src[k], lambda t: re.sub(r'\[@(\w+)\]', lambda m: '[%d]' % num[m.group(1)], t)) for k in order}
unused = [k for k in R if k not in num]
print('refs used:', len(seen), ' unused:', unused)
lines = ["# -*- coding: utf-8 -*-", "# Ibdaa 2027 form v20 (compiled from content_v20_src.py by compile_v20.py).", ""]
for k in ["TITLE_AR", "TITLE_EN", "MAIN_CAT", "SUB_CAT"]:
    lines.append(f"{k} = {src[k]!r}"); lines.append("")
for k in order:
    lines.append(f"{k} = " + pprint.pformat(out_d[k], width=200)); lines.append("")
lines.append("REFS = " + pprint.pformat([R[k] for k in seen], width=200)); lines.append("")
lines.append('SECTIONS = [S1, S2, S3, S4, S5, S6, S7, S8, None]  # section 9 is built from REFS + S9_AI')
lines.append("LIMITS = [(80, 400), (100, 800), (150, 1000), (80, 250), (50, 250), (200, 1000), (50, 1500), (50, 300), None]")
open('content_v20.py', 'w', encoding='utf-8').write("\n".join(lines) + "\n")
