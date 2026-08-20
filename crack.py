#!/usr/bin/env python3
# crack.py — attaque A5/1 complete : my.bursts (chiffre) + plaintext connu -> Kc
#
# Prerequis : deka lance (telnet 0 6666) et find_kc compile.
# Usage :
#   python3 crack.py my.bursts <FN_bloc> <nom_plaintext>
#   ex: python3 crack.py my.bursts 105286 si6_sacch
#
# Etapes (cf. METHODE.md) :
#   1. bloc chiffre = 4 trames consecutives FN..FN+3           (ciphereds.py)
#   2. plaintext connu re-encode en 4 bursts                    (plaintexts.py)
#   3. keystream[i] = chiffre[i] XOR plaintext[i]               (= xor.py de kraken)
#   4. 'crack <keystream>' -> deka -> 'Found <etat> @ <bitpos>'
#   5. find_kc <etat_dec>x <bitpos> <framecount> <framecount2> <keystream2> -> KC MATCHED

import sys, socket, select, time, subprocess
from ciphereds import load, block
from plaintexts import plaintext_bursts

FINDKC='/mnt/kraken/Utilities/find_kc'
HOST,PORT=('127.0.0.1',6666)

def xor(a,b): return ''.join('1' if a[i]!=b[i] else '0' for i in range(114))

def crack_keystreams(keystreams, timeout=1200):
    """Envoie les keystreams a deka, retourne [(etat,bitpos,keystream), ...] des Found."""
    s=socket.socket(); s.connect((HOST,PORT))
    ksset={k for _,k in keystreams}
    for _,k in keystreams:
        s.sendall(("crack %s\n"%k).encode()); time.sleep(0.05)
    crackmap={}; founds=[]; buf=b''; s.setblocking(False); t0=time.time(); done=0
    while time.time()-t0<timeout and done<len(keystreams):
        r,_,_=select.select([s],[],[],3.0)
        if not r: continue
        d=s.recv(16384)
        if not d: break
        buf+=d
        while b'\n' in buf:
            line,buf=buf.split(b'\n',1); t=line.decode('ascii','ignore').rstrip()
            if t.startswith('Cracking'):
                p=t.split(); crackmap[p[1].lstrip('#')]=p[2]
            elif t.startswith('Found'):
                p=t.split(); founds.append((p[1],p[3],crackmap.get(p[4].lstrip('#'))))
                print("  Found",p[1],"@",p[3]); 
            elif 'took' in t:
                done+=1
    s.close(); return founds

def find_kc(state,bitpos,fc,fc2,ks2):
    dec=str(int(state,16))+'x'   # <-- hex -> decimal + 'x' (obligatoire)
    out=subprocess.run([FINDKC,dec,str(bitpos),str(fc),str(fc2),ks2],
                       capture_output=True,text=True).stdout
    for ln in out.splitlines():
        if 'MATCHED' in ln: return ln.strip()
    return None

def main():
    path=sys.argv[1] if len(sys.argv)>1 else 'my.bursts'
    fn0=int(sys.argv[2]); pname=sys.argv[3]
    bursts=load(path)
    blk=block(bursts, fn0)
    if not blk: sys.exit("bloc introuvable a FN %d (il faut FN..FN+3)"%fn0)
    P=plaintext_bursts(pname)
    ks=[]
    for i in range(4):
        count,cbits=blk[i]
        ks.append((count, xor(cbits,P[i])))
        print("burst %d FN %d count %d: ks=%s"%(i,fn0+i,count,ks[-1][1]))
    print("--- deka ---")
    founds=crack_keystreams(ks)
    if not founds: sys.exit("aucun Found (essaie un autre bloc / plaintext)")
    # verification croisee
    kc_by_count={c:k for c,k in ks}
    for state,bitpos,ksval in founds:
        cnt=next((c for c,k in ks if k==ksval), None)
        for c2,k2 in ks:
            if c2==cnt: continue
            m=find_kc(state,bitpos,cnt,c2,k2)
            if m:
                print("\n*** KC TROUVE ***"); print("   ",m); return
    print("\nAucun MATCHED : etats = fausses alarmes. Crack d'autres blocs (voir crack_all.py).")

if __name__=='__main__': main()
