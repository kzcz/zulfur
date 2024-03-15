import ast
import marshal
import binascii
import zlib
import sys
from _sha1 import sha1 as h1
h1=lambda b,q=h1:q(b).digest()
from time import time
from random import choices as ch,choice as coo,randint as rd
ant=ast.NodeTransformer
sod=lambda s,l:set(range(s,s+l))
st=list(sod(65,58)-sod(91,6))+[ord("_")]
st2=st+list(range(48,58))
sai=st2+list((sod(192,256)|sod(452,236)|sod(912,240)|sod(1654,94)|sod(1872,86)|sod(3904,44)|sod(5024,85)|sod(5121,639)|sod(6016,52)|sod(6917,47)|sod(7680,272)|sod(8544,41)|sod(11264,238))-{215,247,930,1014,5741,5742,3912,11493,11494,11495,11496,11497,11498})
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
    return chr(coo(st))+"".join(chr(i) for i in ch(sai,k=rd(2,10)))
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
def ite(ifn):
    if ifn.orelse==[]:
        exh=[ast.ExceptHandler(type=ast.Name(id="BaseException"),body=[ast.Pass()])]
    else:
        ifn.orelse[0]=IF2E().visit(ifn.orelse[0])
        exh=[ast.ExceptHandler(body=ifn.orelse,type=ast.Name(id="OverflowError"))]
    return ast.Try(body=[ast.Expr(value=ast.Call(func=ast.Attribute(value=ast.BinOp(left=ast.Call(func=ast.Name(id="bool"),args=[ifn.test],keywords=[]),op=ast.Sub(),right=ast.Num(n=1)),attr="to_bytes"),args=[],keywords=[]))],handlers=exh,orelse=ifn.body,finalbody=[])
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
            if nt in [ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef]:
                self.cnn(n,"name")
            if nt == ast.arg:
                self.cnn(n,"arg")
            if nt == ast.Global:
                for cp,nm in enumerate(n.names):
                    if (nm not in self.tfd)and(nm not in __builtins__.__dict__):
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
        if (q not in self.tfd)and(q not in __builtins__.__dict__):
            self.tfd[q]=rid()
        if q in self.tfd:
            nd.__setattr__(atn,self.tfd[q])
        return nd
class TSOL(ant):
    td={ord(j):chr(int(i*3.8)+65) for i,j in enumerate('0123456789abcdef')}
    def visit_Bytes(self,node):
        x=node.s.hex().translate(self.td).encode()
        nn=ast.Call(func=ast.Name(id="dc"),keywords=[],args=[ast.Str(s="".join([chr(int.from_bytes(bytes(w),"big")) for w in zip(x[::2],x[1::2])]))])
        ast.copy_location(nn,node)
        ast.fix_missing_locations(nn)
        return nn
    def visit_Str(self,node):
        nn=ast.Call(func=ast.Attribute(value=self.visit_Bytes(ast.Bytes(s=node.s.encode())),attr="decode"),args=[],keywords=[])
        ast.copy_location(nn,node)
        ast.fix_missing_locations(nn)
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
        ast.copy_location(nn,node)
        return nn
def stage1(code):
    code=ast.parse(code)
    print("Stage 1")
    code=TSOL().visit(IF2E().visit(Namer().visit(code)))
    code.body.insert(0,ast.parse("dc=lambda z,td={int(i*3.8)+65:j for i,j in enumerate('0123456789abcdef')}:bytes.fromhex(b\"\".join(ord(c).to_bytes(2,\"big\") for c in z).decode().translate(td))"))
    return ast.unparse(code)
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
    l=[f"from binascii import a2b_base64 as {rbi}",f"from zlib import decompress as {rdi}",f"{exh}=exec",f"{gb}=globals()",f"from _sha1 import sha1 as {hn}",f"{hn}=lambda b,c={hn}:c(b).digest()",f"t=[0,{key}]",f"xv=37",f"{kn}=lambda c,z:1/0 if {hn}(repr([t.copy(),t.__setitem__(0,len(t.append(z[0:4])or t)+len(repr(t)))][0]+[c]).encode())!=z else {exh}({rdi}({rbi}(bytes(xv^i for i in c))).decode(),{gb})"]
    lcb=len(code.body)
    itr=1
    for e in code.body:
        print(f"Converting node {itr}/{lcb}")
        itr+=1
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
        l.append(f"try:\n\traise SyntaxError('Invalid syntax.')\nexcept:\n\t{csn}({kn})/[{csn}.return_{ci}(),{qv}]")
        coc.body.append(mrs(ci,v))
    l=[ast.Assign(targets=[ast.Name(id=bn)],value=ast.Name(id="bytes"),lineno=0),coc]+[ast.parse(e) for e in l]
    code.body=l
    print("Stringo - 1/3")
    code=Stringo().visit(code)
    print("Number - 2/3")
    code=Number().visit(code)
    print("BLD - 3/3")
    code=BLD(bn).visit(code)
    print("Unparse")
    code=ast.unparse(code)
    code="""#===============================#
# Code Obfuscated by Zulfur Obfuscator V1.2
# https://github.com/kzcz/zulfur
# Good luck deobfuscating it
#===============================#
"""+code+"\n\n# Cursed, right? Get Zulfur at https://github.com/kzcz/zulfur"
    return code
def comp(code):
    print("Packing - 1/2")
    c=compile(code,"ZulfurObfuscator","exec")
    c=marshal.dumps(c)
    c=zlib.compress(c)
    c=binascii.b2a_base64(c)
    c=f"exec((i:=globals().__getitem__('__builtins__').__getattribute__('__dict__').__getitem__('__import__'))('marshal').__getattribute__('__dict__').__getitem__('loads')(i('zlib').__getattribute__('__dict__').__getitem__('decompress')(i('binascii').__getattribute__('__dict__').__getitem__('a2b_base64')({c}))))"
    c=ast.parse(c)
    c=BLD("bytes").visit(c)
    c=ast.unparse(c)
    print("Packing - 2/2")
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
        raise e
    else:
        print(f"Obfuscation took {time()-ts:.2f}s.")
    if input(f"Pack (Marshal) file? This will need the file be ran on Python version {'.'.join(str(i) for i in sys.version_info[0:3])} : ").strip().lower() in {"y","yes"}:
        print("Packing file...")
        fc=comp(fc)
    nf=f.replace(".py","_zfobf.py")
    open(nf,"w").write(fc)
    print(f"Obfuscated file: {nf}")
    sys.exit(0)