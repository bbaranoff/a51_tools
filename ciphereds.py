#!/usr/bin/env python3
# ciphereds.py — charge les BURSTS CHIFFRES depuis my.bursts
#
# my.bursts est produit SANS la cle par :
#   grgsm_decode -m TCHF -t 2 -a 514 -s 1083333 -c <cfile> -p -o speech.gsm > my.bursts
# (option -p = print-bursts ; pas de -e/-k -> les bursts restent chiffres)
#
# Format d'une ligne :  <FN> <count>: <114 bits>
#   FN    = numero de trame TDMA
#   count = (t1<<11)|(t3<<5)|t2  (le compteur reduit 22 bits utilise par A5/1)
#
# Un bloc de controle (SDCCH/SACCH) = 4 trames CONSECUTIVES : FN, FN+1, FN+2, FN+3
# (counts espaces de +33). On expose les bursts et un regroupement en blocs.

import sys

def load(path='my.bursts'):
    """Retourne dict: FN -> (count, bits114)"""
    bursts={}
    for line in open(path):
        a=line.split()
        if len(a)<3: continue
        bits=a[2]
        if len(bits)!=114: continue
        bursts[int(a[0])]=(int(a[1].rstrip(':')), bits)
    return bursts

def block(bursts, fn0):
    """Les 4 bursts (count,bits) du bloc commencant a la trame fn0."""
    if not all((fn0+i) in bursts for i in range(4)):
        return None
    return [bursts[fn0+i] for i in range(4)]

if __name__=='__main__':
    path = sys.argv[1] if len(sys.argv)>1 else 'my.bursts'
    b=load(path)
    fns=sorted(b)
    print("bursts:",len(b)," FN",fns[0],"->",fns[-1])
    # exemple : afficher le bloc a la premiere trame
    blk=block(b, fns[0])
    if blk:
        for i,(c,bits) in enumerate(blk):
            print(f"  C{'1' if i==0 else '0'} {fns[0]+i} {c}: {bits}")
