import ast
import marshal
import binascii
import zlib
import sys
from _sha1 import sha1 as h1
h1=lambda b,q=h1:q(b).digest()
from time import time
from random import choices as ch,randint as rd
ant=ast.NodeTransformer
st=list(set(range(65,123))-set(range(91,97)))+[ord("_")]
st2=st+list(range(48,58))
def mrs(vn,st):
    ab=f'{vn}+='
    if type(st)==str:
        l=[vn+'=""']
    else:
        l=[vn+'=b""']
    while len(st):
        i=rd(3,9)
        ci=st[:i]
        st=st[i:]
        l.append(ab+f'{ci!r}')
    l=[ast.parse(x).body[0] for x in l]
    l.append(ast.Return(value=ast.Name(id=vn)))
    n=ast.FunctionDef(name="return_"+vn,body=l,decorator_list=[],args=[],lineno=1)
    return n
def rid():
    return bytes(ch(st,k=rd(5,10))).decode()
def trir():
    return rid()+rid()
def ras(cst=ast.Str):
    bt=bytes(ch(st2,k=rd(2,6)))
    if cst==ast.Str:
        return cst(s=bt.decode())
    return cst(s=bt)
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
    ast.fix_missing_locations(rv)
    return rv
def stbj(st,bn):
    return ast.Call(func=ast.Name(id=bn),args=[ast.List(elts=[ast.Num(n=i) for i in st],ctx=ast.Load())],keywords=[])
class BLD(ant):
    def __init__(self,bn):
        self.bn=bn
    def visit_Bytes(self,node):
        n=stbj(node.s,self.bn)
        ast.copy_location(n,node)
        ast.fix_missing_locations(n)
        return n
    def visit_Str(self,node):
        n=node.s.encode("utf-8")
        n=stbj(n,self.bn)
        n=ast.Call(func=ast.Attribute(value=n,attr='decode'),args=[ast.Str(s="utf-8")],keywords=[])
        ast.copy_location(n,node)
        ast.fix_missing_locations(n)
        return n
class Stringo(ant):
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
        ast.copy_location(rn,node)
        ast.fix_missing_locations(rn)
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
            if nt in [ast.ClassDef,ast.FunctionDef]:
                self.cnn(n,"name")
            if nt == ast.arg:
                self.cnn(n,"arg")
            if nt in [ast.Import,ast.ImportFrom]:
                for al in n.names:
                    if al.asname==None:
                        al.asname=al.name
                    self.cnn(al,"asname")
        return nd
    def cnn(self,nd,atn):
         q=nd.__getattribute__(atn)
         if (q not in self.tfd)and(q not in __builtins__.__dict__):
             self.tfd[q]=rid()
         if q in self.tfd:
             nd.__setattr__(atn,self.tfd[q])
         return nd
class Number(ant):
    def visit_Num(sef,node):
        if 9>node.n:
            return node
        nl=[]
        while node.n>10:
            i=rd(2,10)
            nl.append(i)
            node.n-=i
        nl.append(node.n)
        nl=[ast.Num(n=z) for z in nl]
        return l2add(nl)
def stage1(code):
    code=ast.parse(code)
    return ast.unparse(Namer().visit(code))
def stage2(code):
    code=ast.parse(code)
    code=Number().visit(code)
    csn=trir()
    sli=trir()
    fni=trir()
    anv=trir()
    bn=trir()
    coc=ast.ClassDef(name=csn,keywords=[],bases=[],decorator_list=[],body=[ast.FunctionDef(name="__init__",args=ast.arguments(posonlyargs=[],defaults=[],kwonlyargs=[],args=[ast.arg(arg=sli),ast.arg(arg=fni)]),body=[ast.Assign(targets=[ast.Attribute(value=ast.Name(id=sli),attr=fni)],value=ast.Name(id=fni),lineno=1)],decorator_list=[],lineno=1),ast.FunctionDef(name='__truediv__', args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=sli), ast.arg(arg=anv)], kwonlyargs=[], defaults=[]), body=[ast.Return(value=ast.Call(func=ast.Attribute(value=ast.Name(id=sli), attr=fni), args=[ast.Starred(value=ast.Name(id=anv))], keywords=[]))], decorator_list=[],lineno=1)])
    rbi=trir()
    rdi=trir()
    exh=trir()
    gb=trir()
    kn=trir()
    key=h1(rd(0,256).to_bytes())[0:8]
    hn=trir()
    mrt=[0,key]
    rc=rd(0,256)
    xv=37
    l=[f"from binascii import a2b_base64 as {rbi}",f"from zlib import decompress as {rdi}",f"{exh}=exec",f"{gb}=globals()",f"from _sha1 import sha1 as {hn}",f"{hn}=lambda b,c={hn}:c(b).digest()",f"t=[0,{key}]",f"xv=37",f"{kn}=lambda c,z:1/0 if {hn}(repr([t.copy(),t.__setitem__(0,len(t.append(z[0:4])or t)+len(repr(t)))][0]+[c]).encode())!=z else {exh}({rdi}({rbi}(bytes(xv^i for i in c))),{gb})"]
    for e in code.body:
        nxv=rd(0,256)
        ecn=trir()
        ta=[rid(),nxv]
        ci=rid()
        v=ast.unparse(e)
        v+=f";xv={nxv};t.append({ta})#\033c\033H"
        v=zlib.compress(v.encode())
        v=binascii.b2a_base64(v,newline=0)
        v=bytes(xv^i for i in v)
        xv=nxv
        qv=h1(repr(mrt+[v]).encode())
        mrt.append(qv[0:4])
        mrt[0]=len(mrt)+len(repr(mrt))
        mrt.append(ta)
        l.append(f"try:\n\t1/0\nexcept:\n\t{csn}({kn})/[{csn}.return_{ci}(),{qv}]")
        coc.body.append(mrs(ci,v))
    l=[ast.Assign(targets=[ast.Name(id=bn)],value=ast.Name(id="bytes"),lineno=0),coc]+[ast.parse(e) for e in l]
    code.body=l
    code=Stringo().visit(code)
    code=Number().visit(code)
    code=BLD(bn).visit(code)
    code=ast.unparse(code)
    return code
def comp(code):
    code=marshal.dumps(compile(code,trir(),"exec"))
    code=binascii.b2a_base64(code)
    code=f"""
import marshal as m
import binascii as b
exec(m.loads(b.a2b_base64({code})))
"""
    code=ast.parse(code)
    code=Namer().visit(code)
    code=ast.unparse(code)
    c=ast.parse(f'i=__import__;exec(i("marshal").loads(i("zlib").decompress(i("binascii").a2b_base64({binascii.b2a_base64(zlib.compress(marshal.dumps(compile(code,"ZulfurObfuscator","exec"))),newline=0)}))))')
    c=compile(c,"ZulfurObfuscator","exec")
    c=marshal.dumps(c)
    c=zlib.compress(c)
    c=binascii.b2a_base64(c)
    c=f"exec((i:=globals().__getitem__('__builtins__').__getattribute__('__dict__').__getitem__('__import__'))('marshal').__getattribute__('__dict__').__getitem__('loads')(i('zlib').__getattribute__('__dict__').__getitem__('decompress')(i('binascii').__getattribute__('__dict__').__getitem__('a2b_base64')({c}))))"
    c=ast.parse(c)
    c=BLD("bytes").visit(c)
    c=ast.unparse(c)    
    return f'i=__import__;exec(i("marshal").loads(i("zlib").decompress(i("binascii").a2b_base64({binascii.b2a_base64(zlib.compress(marshal.dumps(compile(code,"ZulfurObfuscator","exec"))),newline=0)}))))' #I Love Marshal
def process(code):
    return stage2(stage1(code))
if __name__=="__main__":
    f=input("Enter file to obfuscate: ").strip()
    if not f.endswith(".py"):
        sys.exit("File must end in .py")
    try:
        of=open(f,"r")
    except:
        sys.exit("Invalid file.")
    else:
        fc=of.read()
        of.close()
    try:
        print(f"Obfuscating file {f}")
        ts=time()
        fc=process(fc)
    except BaseException as e:
        sys.exit(e)
    else:
        print(f"Obfuscation took {time()-ts:.2f}s.")
    if input(f"Pack (Marshal) file? This will need the file be ran on Python version {'.'.join(str(i) for i in sys.version_info[0:3])} : ").strip().lower() in {"y","yes"}:
        print("Packing file...")
        fc=comp(fc)
    nf=f.replace(".py","_zfobf.py")
    open(nf,"w").write(fc)
    print(f"Obfuscated file: {nf}")
    sys.exit(0)