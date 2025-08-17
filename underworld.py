# Copyright 2024-2025 KillZwitch Team
# https://github.com/kzcz
# Author: kzzc@proton.me
# This file is licensed under the GPL version 3 and later

from zfobf import rid,pbz,noise,rd
from base import ask,dver,wca
from base64 import b85encode
from zlib import compress
import marshal, ast
def underworld(code: list[ast.stmt]) -> ast.Module:
    vid_n=rid()
    vid=rd(0,255)
    udwerr=rid()
    rmut_n=rid()
    lst=[f"{vid_n}={vid}","g=globals()","from marshal import loads","from base64 import b85decode","from zlib import decompress","g.update({'m':loads})",f"class {udwerr}(Exception): 0",f"def run(bs):\n\ttry: exec(loads(decompress(b85decode(bs))),g,g)\n\texcept {udwerr}: print('Underworld: Invalid checksum')"]
    for i,x in enumerate(code):
        rmut=[rd(1,255)for _ in [0]*4]
        vid=(((rmut[0]*(vid^rmut[1]) + rmut[2])%521)+rmut[3])&255
        vid_a,vid_b=((vid*3+10)**5)%257,((vid*2+9)**3)%179
        vnb=(vid&vid_b)^vid_a;
        dump=bytes(vnb^((x+i)&255) for i,x in enumerate(marshal.dumps(compile(ast.unparse(x),f"_obj{i}", "exec"))))
        rvid_a,rvid_b,rvnb=rid(),rid(),rid()
        rst=ast.parse(f'{rmut_n}={rmut};{vid_n}=((({rmut_n}[0]*({vid_n}^{rmut_n}[1]) + {rmut_n}[2])%521)+{rmut_n}[3])&255;{rvid_a}=(({vid_n}*3+10)**5)%257\n{rvid_b}=(({vid_n}*2+9)**3)%179\n{rvnb}=({vid_n}&{rvid_b})^{rvid_a}\nif ({rvid_a} != {vid_a}) or ({rvid_b} != {vid_b}): raise {udwerr}\nelse: exec(m(bytes((({rvnb}^x)-i)&255 for i,x in enumerate({dump}))))\n{vid_n}*=17\n{vid_n}+=13\n{vid_n}&=255')
        vid=(vid*17+13)&255
        noise(rst.body,prob=0.84)
        bs=b85encode(compress(marshal.dumps(compile(ast.unparse(rst),'Zulfur','exec'))))
        rst=f"run({bs})"
        lst.append(rst)
    body=[pbz(l) for l in lst]
    noise(body,0.80)
    return ast.Module(body=body,type_ignores=[])
if __name__ == '__main__':
    print(f"Underworld (Zulfur {dver})")
    f=input("File to obfuscate> ").strip()
    if not f.endswith(".py"): exit("File must end with .py")
    try:
        with open(f) as file:
            cnt=file.read()
            udw=underworld(ast.parse(cnt).body)
    except Exception as e:
        exit(f"Exception {e!r} while reading file.")
    out=ast.unparse(udw)
    if ask("Add \"Zulfur\" heading", True):
        out=wca(out)
    outf=f.removesuffix(".py")+"_udw.py"
    try:
        with open(outf,"w") as out_hdl:
            out_hdl.write(out)
    except Exception as e:
        exit(f"Exception {e!r} while reading file.")

