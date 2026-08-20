#!/usr/bin/env python3
# plaintexts.py — PLAINTEXT CONNU (sans la cle) re-encode en bursts de 114 bits
#
# Le plaintext connu de l'attaque A5/1 = les trames LAPDm previsibles cote descendant :
#   - trame de BOURRAGE  (padding 0x2b)         : partout des qu'il n'y a rien a envoyer
#   - SI5 / SI6 sur la SACCH                     : contenu FIXE, lisible en clair sur le BCCH
#     (SI5=06 1d, SI6=06 1e ; le LAI/cell 17 71 00 f1 10 00 01 est identique BCCH<->SACCH)
#
# Une trame SACCH = 23 octets : [L1 header 2o][LAPDm ...][2b padding].
# On les re-encode en 4 bursts via le codeur GSM 05.03 valide (gsmcode).
#
# NB: pour l'attaque reelle "sans clef", on PREDIT ces trames (BCCH + spec).
#     Ici on fournit celles observees dans la capture d'exemple ; adapte a ta cellule.

import os,sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gsmcode import encode_hex

# 23 octets chacune (hex). Le header L1 (2 premiers octets) depend de la cellule.
KNOWN_FRAMES = {
    # bourrage LAPDm descendant (UI + remplissage 2b) — le plus universel
    'fill_sacch': '0000030301'   + '2b'*18,             # 00 00 03 03 01 + 18x2b = 23o
    'fill_lapdm': '03030100'      + '2b'*19,             # sans header L1 (SDCCH)
    # SI5 / SI6 observes sur la SACCH de la capture (header L1 = 07 00 ici)
    'si5_sacch':  '0700030349061d9f02' + '00'*14,       # 07 00 03 03 49 06 1d 9f 02 + 14x00
    'si6_sacch':  '070003032d061e177100f110000127ff' + '2b'*7,  # SI6 SACCH observe
    # SI5 de la doc de reference (header L1 remis a TA=0)
    'si5_doc':    '0000030349061d9f6d1810800000000000000000000000',
}

def plaintext_bursts(name):
    """4 chaines de 114 bits (les 4 bursts plaintext ré-encodés)."""
    h=KNOWN_FRAMES[name]
    assert len(bytes.fromhex(h))==23, "une trame doit faire 23 octets"
    return encode_hex(h)

if __name__=='__main__':
    for n in KNOWN_FRAMES:
        try:
            b=plaintext_bursts(n)
            print(f"{n:12s} -> {len(b)} bursts, burst0={b[0][:32]}...")
        except Exception as e:
            print(f"{n:12s} -> ERREUR {e}")
