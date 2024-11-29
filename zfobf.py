#!/bin/env python
import os
import ast
import marshal
import binascii
import zlib
import sys
from time import perf_counter as time
from random import choices as ch, choice as coo, randint as rd
from itertools import zip_longest as zli
import builtins as vb
from base import ask
op=os.path
vb=vars(vb)
vb.update({"__builtins__":0})
qtp=lambda *a:0
pbz=lambda c:ast.parse(c).body[0]
fac=lambda n,o:[ast.copy_location(n,o),ast.fix_missing_locations(n)] and n
bft=type(id)
mip="Filename must end in .py"
atz=["file","out"]
link="https://github.com/kzcz/zulfur"
valpha,vbeta,vrels=(2,1,0)
ver=(2,0,valpha)
stver='.'.join(str(v) for v in ver[:2])
dver=f"V{stver} ({['Release','Beta','Alpha'][ver[2]]})"
wca=lambda c:f"#===============================#\n# Code Obfuscated by Zulfur Obfuscator V{stver}\n# {link}\n# Good luck deobfuscating it\n#===============================#\n\n{c}\n\n# Cursed, right? Get Zulfur at {link}"
ant=ast.NodeTransformer
aac=ast.Constant
anw=[i for i,j in vb.items() if isinstance(j,type)]
sod=lambda s,l:set(range(s,s+l))
st=list(sod(65,58)-sod(91,6))+[ord("_")]
st2=st+list(range(48,58))
sai=st2+list((sod(192,256)|sod(452,236)|sod(912,240)|sod(1654,94)|sod(1872,86)|sod(3904,44)|sod(5024,85)|sod(5121,639)|sod(6016,52)|sod(6917,47)|sod(7680,272)|sod(8544,41)|sod(11264,238))-sod(11493,6)-{215,247,930,1014,5741,5742,3912})
# symbol list
def rid():
    return chr(coo(st))+"".join(chr(i) for i in ch(sai,k=rd(2,6)))
ZM_STR = 0
ZM_BYTE = 1
def ras(mode: int = ZM_STR):
    bt=bytes(ch(st2,k=rd(2,6)))
    if mode == ZM_STR: bt=bt.decode()
    return aac(value=bt)
def rvg():
    zz=rd(0,2)
    if zz==0:
        return ras(ZM_BYTE)
    if zz==1:
        return ras()
    return aac(value=rd(0,1048576))
def noise(body,prob=0.32):
    l=len(body)
    a=l*(1-prob)
    i=l
    while (i>0):
        qz=rd(0,2)
        if qz==0:
            z=ast.AnnAssign(target=ast.Name(id=rid()),annotation=ast.Name(id=coo(anw)),value=rvg(),simple=1)
        elif qz==1:
            z=ast.Assign(targets=[ast.Name(id=rid())],value=rvg(),lineno=0)
        else:
            z=ast.Expr(value=rvg())
        body.insert(int(i),z)
        i-=a
def ftw(fbo):
    vn=fbo.target
    itn=ast.Name(id=rid())
    bkv=ast.Name(id=rid())
    return [
        ast.Assign(targets=[bkv],value=aac(value=0),lineno=0),
        ast.Assign(targets=[itn],value=ast.Call(func=ast.Name(id="iter"),args=[fbo.iter],keywords=[]),lineno=0),
        ast.While(
            test=aac(value=1),
            body=[
                ast.Try(body=[
                    ast.Assign(targets=[vn],value=ast.Call(func=ast.Name(id="next"),args=[itn],keywords=[]),lineno=0)
                ]+fbo.body,
                handlers=[
                    ast.ExceptHandler(type=ast.Name(id="StopIteration"),body=[
                        ast.Assign(targets=[bkv],value=aac(value=1),lineno=0),ast.Break()
                    ])],
                orelse=[],
                finalbody=[])
            ],
            orelse=[])
    ] + ([ast.If(test=bkv,body=fbo.orelse,orelse=[])] if fbo.orelse else [])
def ftf(body):
    for i in body:
        if "body" in i._fields:
            ftf(i.body)
        if "orelse" in i._fields:
            ftf(i.orelse)
        if "handlers" in i._fields:
            for j in i.handlers:
                ftf(j.body)
        if isinstance(i,ast.For):
            r=ftw(i)[::-1]
            q=body.index(i)
            body.pop(q)
            for j in r:
                body.insert(q,j)
def tna(body):
    for i in body:
        if "body" in i._fields:
            tna(i.body)
        if "orelse" in i._fields:
            tna(i.orelse)
        if "handlers" in i._fields:
            for j in i.handlers:
                tna(j.body)
    noise(body)
def l2add(ls):
    if len(ls)<1:
        return ls
    e=ls.pop(0)
    while len(ls):
        e=ast.BinOp(left=e,op=ast.Add(),right=ls.pop(0),lineno=1,col_offset=0)
    return e
def befso(e,mode=ZM_STR):
    j=rd(2,len(e.value)+4)
    i=rd(int(j//2),j)
    z=[ras(mode) for _ in range(j)]
    z.insert(i,e)
    return ast.Subscript(
        value=ast.List(elts=z),
        slice=aac(value=i),
        ctx=ast.Load(),
        lineno=0
    )
def stbj(st,bn):
    return ast.Call(func=ast.Name(id=bn),args=[ast.List(elts=[aac(value=i) for i in st],ctx=ast.Load())],keywords=[])
def ite(ifn):
    exh=ast.ExceptHandler(type=ast.Name(id="ZeroDivisionError"))
    if ifn.orelse==[]:
        exh.body=[ast.Pass()]
    else:
        exh.body=IF2E().visit(ast.Module(body=ifn.orelse)).body
    return ast.Try(body=[ast.Expr(value=ast.BinOp(left=aac(value=1),op=ast.Div(),right=ifn.test))],handlers=[exh],orelse=ifn.body,finalbody=[])
class BLD(ant):
    def __init__(self,bn):
        self.bn=bn
    def visit_JoinedStr(self,node):
        return node
    def visit_Constant(self, node):
        v=node.value; t=type(v)
        if t not in [str,bytes]:
            return node
        if t==str: v=v.encode("utf-8")
        n=stbj(v,self.bn)
        if t==str: n=ast.Call(func=ast.Attribute(value=n,attr='decode'),args=[aac(value="utf-8")],keywords=[])
        return fac(n,node)
class Stringo(ant):
    def __init__(self):
        self. vn=set()
    def visit_JoinedStr(self,node):
        return node
    def visit_Constant(self,node):
        v=node.value; t=type(v);
        if (mode:=ZM_STR if t==str else ZM_BYTE if t==bytes else -1)==-1: return node
        if len(v)<2: return node
        l=[]
        ctr=0
        vz=[]
        while len(v):
            if ctr>250:
                vz.append(aac(value=v))
                break
            i=rd(2,10)
            ta=befso(aac(value=v[0:i]),mode)
            l.append(ta)
            v=v[i:]
            ctr+=1
        l.extend(vz)
        rn=l2add(l)
        self.vn.add(id(rn))
        fac(rn,node)
        return rn
    def visit_BinOp(self,node):
        if id(node) in self.vn:
            return node
        return super().generic_visit(node)
class Namer(ant):
    def __init__(self):
        self.tfd={}
    def visit(self,nd):
        for n in ast.walk(nd):
            nt=type(n)
            if nt == ast.Name:
                self.cnn(n,"id")
            if nt == ast.ExceptHandler:
                if n.type:
                    self.cnn(n,"name")
            if nt in [ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef]:
                self.cnn(n,"name")
            if nt == ast.arg:
                self.cnn(n,"arg")
            if nt == ast.Global:
                for cp,nm in enumerate(n.names):
                    if (nm not in self.tfd)and(nm not in vb):
                        self.tfd[nm]=rid()
                    if nm in self.tfd:
                        n.names[cp]=self.tfd[nm]
            if nt in [ast.Import,ast.ImportFrom]:
                for al in n.names:
                    if al.asname==None:
                        al.asname=al.name
                    self.cnn(al,"asname")
        return nd
    def cnn(self,nd,atn):
        q=getattr(nd,atn)
        if (q not in self.tfd)and(q not in vb):
            self.tfd[q]=rid()
        if q in self.tfd:
            setattr(nd,atn,self.tfd[q])
        return nd
class TSOL(ant):
    td={ord(j):chr(int(i*3.8)+65) for i,j in enumerate('0123456789abcdef')}
    def __init__(self):
        self.vn=set()
    def visit_Bytes(self,node):
        if id(node) in self.vn:
            return node
        x=node.value.hex().translate(self.td).encode()
        s=aac(value="".join([chr(int.from_bytes(bytes(w),"big")) for w in zip(x[::2],x[1::2])]))
        self.vn.add(id(s))
        nn=ast.Call(func=ast.Name(id="dc"),keywords=[],args=[s])
        fac(nn,node)
        return nn
    def visit_JoinedStr(self,node):
        return node
    def visit_Str(self,node):
        if id(node) in self.vn:
            return node
        nn=ast.Call(func=ast.Attribute(value=self.visit_Bytes(aac(value=node.value.encode())),attr="decode"),args=[aac(value="utf-8")],keywords=[])
        fac(nn,node)
        return nn
class IF2E(ant):
    def visit_If(self,node):
        nn=ite(node)
        fac(nn,node)
        return nn
class HBF(ant):
    def __init__(self,twl):
        self.l={f:pbz(f"{twl}('{f}')").value for f in (i for i,j in vb.items() if type(j)==bft)}
    def visit_Call(self,node):
        f=node.func
        if type(f)==ast.Name:
            if f.id in self.l:
                node.func=self.l[f.id]
        return node
def rfrm(fp,fc=None,m="r"):
    if op.isdir(fp):
        sys.exit(f"{fp} is a directory.")
    try:
        with open(fp,m) as fh:
            if m=="r":
                return fh.read()
            if m=="w":
                return fh.write(fc)
    except Exception as e:
        sys.exit(f"Error ocurred while accessing file {fp}: {e}: {', '.join(str(i) for i in e.args)}")
class AG2O(ant):
	def visit_AugAssign(self,node):
		nn=ast.Assign(targets=[node.target],value=ast.BinOp(left=node.target,op=node.op,right=node.value))
		fac(nn,node)
		return nn
def stage1(code,flags=0,print=qtp):
    code=ast.parse(code)
    i=ast.Pass()
    fac(i,code)
    print("Stage 1")
    code=Namer().visit(AG2O().visit(IF2E().visit(code)))
    twl='' # keep warnings quiet
    if flags&1:
        print("Hide Builtins")
        twl=rid()
        code=HBF(twl).visit(code)
    print("Stringo")
    code=Stringo().visit(code)
    print("TSOL")
    code=TSOL().visit(code)
    cb=code.body
    print("Noise")
    tna(cb)
    ftf(cb)
    iz=lambda l:cb.insert(0,pbz(l))
    iz("dc=lambda z,td={int(i*3.8)+65:j for i,j in enumerate('0123456789abcdef')}:bytes.fromhex(b\"\".join(ord(c).to_bytes(2,\"big\") for c in z).decode().translate(td))")
    if flags&1:
        iz(f"{twl}=lambda nm: getattr(__import__('builtins'),'nm')")
    fac(code,i)
    return ast.unparse(code)
def comp(code,flags=0,print=qtp):
    print("Packing - 1/2")
    c=ast.unparse([d:=ast.parse(ast.dump(ast.parse(code))),[setattr(i.func,'id','ast.'+i.func.id) for i in ast.walk(d) if isinstance(i,ast.Call)]][0]).encode()
    c=zlib.compress(c)
    c=binascii.b2a_base64(c)
    c=f"type(lambda:0)(compile((ast:=__import__('ast')).fix_missing_locations(eval(__import__('zlib').decompress(__import__('binascii').a2b_base64({c})))),'','exec'),globals())()"
    c=ast.parse(c)
    c=BLD("bytes").visit(c)
    c=ast.unparse(c)
    print("Packing - 2/2")
    return f'i=__import__;exec(i("marshal").loads(i("zlib").decompress(i("binascii").a2b_base64({binascii.b2a_base64(zlib.compress(marshal.dumps(compile(code,"ZulfurObfuscator","exec"))),newline=False)}))))' #I Love Marshal
def process(code,f=[0,0],ff=0,print=qtp):
    code=stage1(code,f[0],print)
    if ff&1:
        code=comp(code,f[1],print)
    if ff&128:
        code=wca(code)
    return code
if __name__=="__main__":
    yv=sys.argv[1:]
    ls=len(yv)
    if ls>0:
        if ls>len(atz):
            sys.exit("Usage: file [out_file]")
        d=dict(zli(atz,yv))
        f,o=d.values()
        if not f.endswith(".py"):
            sys.exit(mip)
        if not o:
            o=f[:-3]+"_zfobf.py"
        fc=rfrm(f)
        oc=process(fc)
        rfrm(o,oc,"w")
        sys.exit(0)
    print("Zulfur Obfuscator",dver)
    f=input("Enter file to obfuscate: ").strip()
    if not f.endswith(".py"):
        sys.exit(mip)
    fc=rfrm(f)
    fl=[0,0]
    ff=128
    pt=qtp
    if ask("Quiet mode", True):
        pt=print
    if ask("Hide builtin names", False):
        fl[0]|=1
    if ask("Compress code", False):
        ff|=1
    if ask("Disable code wrapping", False):
        ff^=128
    print(f"Obfuscating file {f}")
    ts=time()
    fc=process(fc,fl,ff,pt)
    print(f"Obfuscation took {time()-ts}")
    nf=f.replace(".py","_zfobf.py")
    open(nf,"w").write(fc)
    print(f"Obfuscated file: {nf}")
    sys.exit(0)
