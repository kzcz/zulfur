import os
import ast
import marshal
import binascii
import zlib
import sys
from _sha1 import sha1 as h1
from time import perf_counter as time
from random import choices as ch,choice as coo,randint as rd
op=os.path
vb=vars(__import__("builtins"))
gta=lambda a,b:object.__getattribute__(a,b)
gpi=lambda txt:input(txt).lower().strip()
qtp=lambda *a,**k:0
pbz=lambda c:ast.parse(c).body[0]
h1=lambda b,q=h1:q(b).digest()
fac=lambda n,o:[ast.copy_location(n,o),ast.fix_missing_locations(n)]
ft=type(gta)
ct=type(gta.__code__)
ptv=["yes","w","h","y","1"]
pfv=["no","n","l","0"]
bft=type(id)
mip="Filename must end in .py"
pl=["argcount","posonlyargcount","kwonlyargcount","nlocals","stacksize","flags","code","consts","names","varnames","filename","name","qualname","firstlineno","linetable","exceptiontable","freevars","cellvars"]
atz=["file","out"]
link="https://github.com/kzcz/zulfur"
l0="(lambda:0)"
dfn=f"type{l0}"
dcn=f"type({l0}.__code__)"
valpha,vbeta,vrels=(2,1,0)
ver=(1,5,vrels)
stver='.'.join(str(v) for v in ver[0:2])
dver=f"V{stver} ({['Release','Beta','Alpha'][ver[2]]})"
wca=lambda c:f"#===============================#\n# Code Obfuscated by Zulfur Obfuscator V{stver}\n# {link}\n# Good luck deobfuscating it\n#===============================#\n\n{c}\n\n# Cursed, right? Get Zulfur at {link}"
ant=ast.NodeTransformer
anw=[i for i,j in vb.items() if isinstance(j,type)]
sod=lambda s,l:set(range(s,s+l))
st=list(sod(65,58)-sod(91,6))+[ord("_")]
st2=st+list(range(48,58))
sai=st2+list((sod(192,256)|sod(452,236)|sod(912,240)|sod(1654,94)|sod(1872,86)|sod(3904,44)|sod(5024,85)|sod(5121,639)|sod(6016,52)|sod(6917,47)|sod(7680,272)|sod(8544,41)|sod(11264,238))-sod(11493,6)-{215,247,930,1014,5741,5742,3912})
class litr:
    def __init__(self,a):
        self.a=a
    def __repr__(self):
        return self.a
def cotc(co,cn=dcn):
    dv={k:gta(co,"co_"+k) for k in pl}
    cst=list(dv["consts"])
    for i,v in enumerate(cst):
        if type(v)==ct:
            cst[i]=litr(cotc(v,cn))
    dv["consts"]=tuple(cst)
    return f"{cn}{tuple(dv.values())}"
def fdtc(fd,fn=dfn,cn=dcn):
    return f"{fn}({cotc(fd.__code__,cn)},globals(),{fd.__name__!r})"
def rid():
    return chr(coo(st))+"".join(chr(i) for i in ch(sai,k=rd(2,7)))
def ras(cst=ast.Str):
    bt=bytes(ch(st2,k=rd(2,6)))
    if cst==ast.Str:
        return cst(s=bt.decode())
    return cst(s=bt)
def rvg():
    zz=rd(0,2)
    if zz==0:
        return ras(ast.Bytes)
    if zz==1:
        return ras()
    return ast.Num(n=rd(0,1048576))
def noise(body,pon=0.32):
    l=len(body)
    a=l*(1-pon)
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
    return [ast.Assign(targets=[bkv],value=ast.Num(n=0),lineno=0),ast.Assign(targets=[itn],value=ast.Call(func=ast.Name(id="iter"),args=[fbo.iter],keywords=[]),lineno=0),ast.While(test=ast.Num(n=1),body=[ast.Try(body=[ast.Assign(targets=[vn],value=ast.Call(func=ast.Name(id="next"),args=[itn],keywords=[]),lineno=0)]+fbo.body,handlers=[ast.ExceptHandler(type=ast.Name(id="StopIteration"),body=[ast.Assign(targets=[bkv],value=ast.Num(n=1),lineno=0),ast.Break()])],orelse=[],finalbody=[])],orelse=[])]+([ast.If(test=bkv,body=fbo.orelse,orelse=[])] if fbo.orelse else [])
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
def befso(e,cst=ast.Str):
    j=rd(2,len(e.s)+4)
    i=rd(int(j//2),j)
    z=[ras(cst) for i in range(j)]
    z.insert(i,e)
    rv=ast.Subscript(value=ast.List(elts=z),slice=ast.Index(value=ast.Num(n=i)),ctx=ast.Load(),lineno=0)
    return rv
def stbj(st,bn):
    return ast.Call(func=ast.Name(id=bn),args=[ast.List(elts=[ast.Num(n=i) for i in st],ctx=ast.Load())],keywords=[])
def ite(ifn):
    exh=ast.ExceptHandler(type=ast.Name(id="ZeroDivisionError"))
    if ifn.orelse==[]:
        exh.body=[ast.Pass()]
    else:
        exh.body=IF2E().visit(ast.Module(body=ifn.orelse)).body
    return ast.Try(body=[ast.Expr(value=ast.BinOp(left=ast.Num(n=1),op=ast.Div(),right=ast.UnaryOp(op=ast.Not(),operand=ifn.test,keywords=[])))],handlers=[exh],orelse=ifn.body,finalbody=[])
class FTO(ant):
    def __init__(self,fn,cn):
        self.fn=fn
        self.cn=cn
    def visit_Lambda(self,node):
        f=pbz(fdtc(eval(ast.unparse(node)),self.fn,self.cn)).value
        fac(f,node)
        return f
    def visit_AsyncFunctionDef(self,node):
        return self.visit_FunctionDef(node)
    def visit_FunctionDef(self,node):
        d={}
        n=node.name
        exec(ast.unparse(node),globals(),d)
        f=pbz(f"{n}={fdtc(*d.values(),self.fn,self.cn)}")
        fac(f,node)
        return f
class BLD(ant):
    def __init__(self,bn):
        self.bn=bn
    def visit_JoinedStr(self,node):
        return node
    def visit_Bytes(self,node):
        n=stbj(node.s,self.bn)
        fac(n,node)
        return n
    def visit_Str(self,node):
        n=node.s.encode("utf-8")
        n=stbj(n,self.bn)
        n=ast.Call(func=ast.Attribute(value=n,attr='decode'),args=[ast.Str(s="utf-8")],keywords=[])
        fac(n,node)
        return n
class Stringo(ant):
    def visit_JoinedStr(self,node):
        return node
    def visit_Str(self,node,cst=ast.Str):
        if len(node.s)<1:
            return node
        l=[]
        while len(node.s):
            i=rd(2,7)
            ta=befso(cst(s=node.s[0:i]),cst)
            ast.fix_missing_locations(ta)
            l.append(ta)
            node.s=node.s[i:]
        rn=l2add(l)
        fac(rn,node)
        return rn
    def visit_Bytes(self,node):
        return self.visit_Str(node,ast.Bytes)
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
        q=nd.__getattribute__(atn)
        if (q not in self.tfd)and(q not in vb):
            self.tfd[q]=rid()
        if q in self.tfd:
            nd.__setattr__(atn,self.tfd[q])
        return nd
class TSOL(ant):
    td={ord(j):chr(int(i*3.8)+65) for i,j in enumerate('0123456789abcdef')}
    def visit_Bytes(self,node):
        x=node.s.hex().translate(self.td).encode()
        nn=ast.Call(func=ast.Name(id="dc"),keywords=[],args=[ast.Str(s="".join([chr(int.from_bytes(bytes(w),"big")) for w in zip(x[::2],x[1::2])]))])
        fac(nn,node)
        return nn
    def visit_JoinedStr(self,node):
        return node
    def visit_Str(self,node):
        nn=ast.Call(func=ast.Attribute(value=self.visit_Bytes(ast.Bytes(s=node.s.encode())),attr="decode"),args=[],keywords=[])
        fac(nn,node)
        return nn
class Number(ant):
    def visit_Num(sef,node):
        if 9>node.n:
            return node
        if node.n>2000:
            return node
        nl=[]
        while node.n>10:
            i=rd(2,10)
            nl.append(i)
            node.n-=i
        nl.append(node.n)
        nl=[ast.Num(n=z) for z in nl]
        return l2add(nl)
class IF2E(ant):
    def visit_If(self,node):
        nn=ite(node)
        fac(nn,node)
        return nn
class HBF(ant):
    def __init__(self,twl):
        self.t=twl
        self.l={f:pbz(f"{twl}('{f}')").value for f in (i.__name__ for i in vb.values() if type(i)==bft)}
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
        fh=open(fp,m)
        if m=="r":
            return fh.read()
        if m=="w":
            return fh.write(fc)
    except BaseException as b:
        sys.exit(f"Error ocurred while accessing file {fp}: {b}: {', '.join(str(i) for i in b.args)}")
    finally:
        fh.close()
def stage1(code,flags=0,print=qtp):
    code=ast.parse(code)
    print("Stage 1")
    code=IF2E().visit(Namer().visit(code))
    if flags&1:
        print("Funtion Obfuscation")
        fn,cn=rid(),rid()
        code=FTO(fn,cn).visit(code)
    if flags&2:
        print("Hide Builtins")
        twl=rid()
        code=HBF(twl).visit(code)
    print("TSOL")
    code=TSOL().visit(Stringo().visit(code))
    cb=code.body
    print("Noise")
    tna(cb)
    ftf(cb)
    cb.insert(0,pbz("dc=lambda z,td={int(i*3.8)+65:j for i,j in enumerate('0123456789abcdef')}:bytes.fromhex(b\"\".join(ord(c).to_bytes(2,\"big\") for c in z).decode().translate(td))"))
    if flags&1:
        cb.insert(0,pbz(f"{cn}={dcn}"))
        cb.insert(0,pbz(f"{fn}={dfn}"))
    if flags&2:
        bsz="\\x00"
        cb.insert(0,pbz(f"{twl}=lambda nm:type({twl})(type({twl}.__code__)(0,0,0,2,5,15,b'\\x97\\x00t\\x01{bsz*10}|\\x00i\\x00|\\x01\\xa4\\x01\\x8e\\x01S\\x00',(None,),(nm,),('a','k'),'<NULL>',nm,nm,1,b'\\x80\\x00\\x88\\x01\\x80\\x00',b'',(),()),globals())"))
    return ast.unparse(code)
def comp(code,flags=0,print=qtp):
    print("Packing - 1/2")
    c=ast.unparse([d:=ast.parse(ast.dump(ast.parse(code))),[i.func.__setattr__('id','ast.'+i.func.id) for i in ast.walk(d) if isinstance(i,ast.Call)]][0]).encode()
    c=zlib.compress(c)
    c=binascii.b2a_base64(c)
    c=f"type(lambda:0)(compile((ast:=__import__('ast')).fix_missing_locations(eval(__import__('zlib').decompress(__import__('binascii').a2b_base64({c})))),'','exec'),globals())()"
    c=ast.parse(c)
    c=BLD("bytes").visit(c)
    c=ast.unparse(c)
    print("Packing - 2/2")
    return f'i=__import__;exec(i("marshal").loads(i("zlib").decompress(i("binascii").a2b_base64({binascii.b2a_base64(zlib.compress(marshal.dumps(compile(code,"ZulfurObfuscator","exec"))),newline=0)}))))' #I Love Marshal
def process(code,f=[0,0,0],ff=0,print=qtp):
    code=stage1(code,f[0],print)
    if ff&1:
        code=comp(code,f[2],print)
    if ff&128:
        code=wca(code)
    return code
if __name__=="__main__":
    yv=sys.argv[1:]
    ls=len(yv)
    if ls>0:
        if ls>len(atz):
            sys.exit("Usage: file [out]")
        d=dict((k,None) for k in atz)
        d.update(dict(zip(atz,yv)))
        f=d["file"]
        if not f.endswith(".py"):
            sys.exit(mip)
        o=d["out"]
        if not o:
            o=f.replace(".py","_zfobf.py")
        fc=rfrm(f)
        oc=process(fc)
        rfrm(o,oc,"w")
        sys.exit(0)
    print("Zulfur Obfuscator",dver)
    f=input("Enter file to obfuscate: ").strip()
    if not f.endswith(".py"):
        sys.exit(mip)
    fc=rfrm(f)
    fl=[0,0,0]
    ff=128
    pt=qtp
    if gpi("Quiet mode? <Def=Yes> ") in pfv:
        pt=print
    if gpi("Version dependant code? <Def=No> ") in ptv:
        fl[0]|=1
        if gpi("Hide builtin names? <Def=No>") in ptv:
            fl[0]|=2
        if gpi("Compress code? <Def=No> ") in ptv:
            ff|=1
    if gpi("Disable code wrapping? <Def=No> ") in ptv:
        ff^=128
    try:
        print(f"Obfuscating file {f}")
        ts=time()
        fc=process(fc,fl,ff,pt)
    except BaseException as e:
        raise e
    print(f"Obfuscation took {time()-ts}")
    nf=f.replace(".py","_zfobf.py")
    open(nf,"w").write(fc)
    print(f"Obfuscated file: {nf}")
    sys.exit(0)