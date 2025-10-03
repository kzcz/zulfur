link="https://github.com/kzcz/zulfur"
valpha,vbeta,vrels=(2,1,0)
ver=(2,1,vrels)
stver='.'.join(str(v) for v in ver[:2])
dver=f"V{stver} ({['Release','Beta','Alpha'][ver[2]]})"
wca=lambda c:f"#===============================#\n# Code Obfuscated by Zulfur Obfuscator V{stver}\n# {link}\n# Good luck deobfuscating it\n#===============================#\n\n{c}\n\n# Cursed, right? Get Zulfur at {link}"

def ask(qst: str, df: bool) -> bool:
    i=input(f"{qst}? <Def={'YNeos'[1-df::2]}> ").strip().lower()
    if not i: return df
    if df: return i not in ["no","n","nao","0"]
    return i in ["yes","ye","y","si","s","1"]
