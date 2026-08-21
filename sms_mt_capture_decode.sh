#!/usr/bin/env bash
# =============================================================================
#  sms_mt_capture_decode.sh
#  Envoie un MT SMS (reseau -> mobile), capture l'air DESCENDANT dans un cfile,
#  recupere le Kc de session, decoupe la fenetre, decode le SMS avec grgsm et
#  reconstitue le texte 7-bit.
#
#  CONTEXTE : pile Calypso en CALYPSO_BRIDGE=pont, a5/1, dans le conteneur
#  osmo-operator-1. Le pont enregistre l'air descendant en continu dans
#  /root/record.cfile (modulation GMSK avec encodage differentiel gr-gsm).
#
#  ROLE : Claude a valide ce flux le 16/08/2026 ; texte 'BASTIEN-MT-TEST-66'
#  retrouve depuis le cfile. grgsm ne decode QUE le descendant : un MO SMS
#  (mobile -> reseau) part en montant et reste illisible. Il FAUT un MT SMS.
#
#  USAGE :
#    ./sms_mt_capture_decode.sh <MSISDN_DEST> <MSISDN_EXP> "<texte>"
#  Ex :
#    ./sms_mt_capture_decode.sh 10001 10002 "BASTIEN-MT-TEST-66"
#
#  Le mobile enregistre (celui dont on lit l'air) est le DEST.
# =============================================================================
set -euo pipefail

CTR="${CTR:-osmo-operator-1}"          # conteneur de la pile
DEST="${1:-10001}"                     # abonne cible = mobile enregistre
EXP="${2:-10002}"                      # expediteur affiche
TEXT="${3:-BASTIEN-MT-TEST-66}"
ARFCN="${ARFCN:-514}"
SR="${SR:-1083333}"
RECORD="${RECORD:-/root/record.cfile}" # cfile continu ecrit par le pont
KCFILE="${KCFILE:-/dev/shm/calypso_kc}"  # Kc de session (transitoire, octets 6..13)
VTY_MSC="${VTY_MSC:-4254}"
OUT="${OUT:-/root/sms_slice.cfile}"    # tranche produite (hote)
KC_OVERRIDE="${4:-${KC_OVERRIDE:-}}"   # Kc impose si la session NE re-chiffre pas
#  ^ la pile ne re-authentifie pas a chaque SMS : si le contexte de securite est
#    reutilise, /dev/shm/calypso_kc n'est PAS reecrit et reste a 0. Passe alors
#    le dernier Kc connu en 4e argument pour decoder quand meme.

echo "== 0. controles =="
docker exec "$CTR" test -f "$RECORD" || { echo "PAS de $RECORD dans $CTR (pont actif ?)"; exit 1; }
command -v grgsm_decode >/dev/null   || { echo "grgsm_decode absent du PATH hote"; exit 1; }

# --- client VTY minimal, depose dans le conteneur ---
docker exec "$CTR" sh -c 'cat > /root/_vty.py <<'"'"'PY'"'"'
import socket,sys,time
s=socket.socket(); s.settimeout(5); s.connect(("127.0.0.1",int(sys.argv[1])))
def rd():
    time.sleep(0.4); b=b""; s.setblocking(False)
    try:
        while True: b+=s.recv(4096)
    except: pass
    s.setblocking(True); return b.decode("utf-8","replace")
rd()
for c in sys.argv[2:]:
    s.sendall((c+"\r\n").encode()); rd()
PY'

echo "== 1. offset AVANT =="
OFF0=$(docker exec "$CTR" stat -c %s "$RECORD"); echo "   $OFF0"

echo "== 2. envoi MT SMS $EXP -> $DEST : \"$TEXT\" =="
docker exec "$CTR" python3 /root/_vty.py "$VTY_MSC" \
    "enable" "subscriber msisdn $DEST sms sender msisdn $EXP send $TEXT"

echo "== 3. attente de la transaction ENTIERE (paging -> auth -> SDCCH -> RP-DATA) =="
sleep 20
OFF1=$(docker exec "$CTR" stat -c %s "$RECORD"); echo "   offset APRES = $OFF1"

echo "== 4. Kc via la VTY (source FIABLE) =="
# /dev/shm/calypso_kc reste a 0 quand le contexte de securite est REUTILISE
# (pas de re-authentification). La VTY, elle, garde le tuple courant :
#   MSC 4254 : "show subscriber msisdn <X>" -> ligne "Kc    : ee 3b .."
#   mobile 4247 : "show subscriber"         -> "Key: sequence N  ee 3b .."
# On lit le MSC d'abord, le mobile en secours, puis $KC_OVERRIDE.
kc_from_vty() {  # $1=port  $2...=commandes ; imprime 16 hexa ou vide
  # -i INDISPENSABLE : sans lui, docker exec ne transmet PAS le heredoc sur
  # stdin, python3 lit un flux vide et n'imprime rien (le bug qui renvoyait "").
  docker exec -i "$CTR" python3 - "$@" <<'PY'
import sys,socket,time,re
port=int(sys.argv[1]); cmds=sys.argv[2:]
s=socket.socket(); s.settimeout(6); s.connect(("127.0.0.1",port))
def rd():
    time.sleep(0.5); b=b""; s.setblocking(False)
    try:
        while True: b+=s.recv(8192)
    except: pass
    s.setblocking(True); return b.decode("utf-8","replace")
out=rd()
for c in cmds: s.sendall((c+"\r\n").encode()); out+=rd()
m=re.search(r"(?:Kc\s*:|Key:\s*sequence\s*\d+)\s*((?:[0-9a-fA-F]{2}\s*){8})", out)
print(re.sub(r"\s","",m.group(1)).lower() if m else "")
PY
}
KC=$(kc_from_vty "$VTY_MSC" "enable" "show subscriber msisdn $DEST")
[ -z "$KC" -o "$KC" = "0000000000000000" ] && KC=$(kc_from_vty 4247 "enable" "show subscriber")
if [ -n "$KC" ] && [ "$KC" != "0000000000000000" ]; then
  echo "   Kc=$KC (VTY)"
elif [ -n "$KC_OVERRIDE" ]; then
  KC="$KC_OVERRIDE"; echo "   Kc=$KC (secours 4e arg)"
else
  KC=""; echo "   !! aucun Kc via VTY ni secours — on tentera EN CLAIR"
fi

echo "== 5. decoupe de la fenetre =="
LEN=$((OFF1-OFF0))
SEC=$(python3 -c "print(round($LEN/8/$SR,1))")
echo "   fenetre = $((LEN/1000000)) Mo (~${SEC}s)"
python3 -c "import sys; sys.exit(0 if $LEN>60000000 else 1)" || \
  echo "   !! fenetre courte (<~7s) : le RP-DATA peut manquer. Envoi non delivre ?"
docker exec "$CTR" dd if="$RECORD" of=/root/_sms_slice.cfile \
    bs=8M iflag=skip_bytes,count_bytes skip="$OFF0" count="$LEN" status=none
docker cp "$CTR":/root/_sms_slice.cfile "$OUT" >/dev/null
echo "   $OUT ($(du -h "$OUT" | cut -f1))"

echo "== 6. decodage + reassemblage SMS =="
# Avec Kc -> dechiffrement A5/1. Sans Kc -> tentative EN CLAIR : si la session
# n'a pas (re)chiffre (a5/0 ou contexte reutilise sans cipher), le SMS est en
# clair dans le cfile et se decode sans cle.
if [ -n "$KC" ]; then KEYARGS="-e 1 -k $KC"; echo "   mode : dechiffre (Kc=$KC)"
else KEYARGS=""; echo "   mode : EN CLAIR (aucun Kc — on tente sans dechiffrement)"; fi

PCAP=/root/_sms_probe.pcap
# Balaye SDCCH/4 (combine C0) puis SDCCH/8 (TS1) et RETIENT la 1re config qui
# sort du SAPI3, pour pouvoir echoter la commande EXACTE (bon -m -t -u).
count_sapi3() {  # $1=pcap -> nb de frames SAPI3
  python3 - "$1" <<'PY'
import struct,sys
d=open(sys.argv[1],"rb").read(); off=24; n=0
while off+16<=len(d):
    _,_,c,_=struct.unpack("<IIII",d[off:off+16]); off+=16; pkt=d[off:off+c]; off+=c
    for b in range(40,56):
        if b+16<=len(pkt) and pkt[b]==0x02:
            pl=pkt[b+pkt[b+1]*4:]
            if len(pl)>=3 and ((pl[0]>>2)&7)==3: n+=1
            break
print(n)
PY
}
WIN_M=""; WIN_T=""; WIN_U=""
probe() {  # $1=mode $2=timeslot $3=subslot
  local p=/root/_probe_$1_$2_$3.pcap
  tcpdump -i lo -w "$p" "udp port 4729" >/dev/null 2>&1 & local td=$!
  sleep 0.6
  timeout 120 grgsm_decode -m "$1" -t "$2" -u "$3" -a "$ARFCN" -s "$SR" -c "$OUT" $KEYARGS 2>/dev/null || true
  sleep 1; kill -INT $td 2>/dev/null || true; sleep 0.4; kill $td 2>/dev/null || true; wait 2>/dev/null || true
  if [ "$(count_sapi3 "$p")" -gt 0 ] && [ -z "$WIN_M" ]; then
    WIN_M="$1"; WIN_T="$2"; WIN_U="$3"; cp "$p" "$PCAP"
    echo "   -> SAPI3 sur -m $1 -t $2 -u $3"
  fi
  rm -f "$p"
}
for u in 0 1 2 3; do probe BCCH_SDCCH4 0 "$u"; [ -n "$WIN_M" ] && break; done
[ -z "$WIN_M" ] && for u in 0 1 2 3 4 5 6 7; do probe SDCCH8 1 "$u"; [ -n "$WIN_M" ] && break; done

if [ -z "$WIN_M" ]; then
  echo "   Aucune frame SAPI3 sur aucune sous-voie."
  echo "   -> mauvais Kc ? SMS non delivre (fenetre courte) ? MO au lieu de MT ?"
  exit 3
fi

python3 - "$PCAP" <<'PY'
import struct,sys
d=open(sys.argv[1],"rb").read(); off=24; frames=[]
while off+16<=len(d):
    _,_,cap,_=struct.unpack("<IIII",d[off:off+16]); off+=16
    pkt=d[off:off+cap]; off+=cap
    for b in range(40,56):
        if b+16<=len(pkt) and pkt[b]==0x02:
            pl=pkt[b+pkt[b+1]*4:]
            if len(pl)>=3 and ((pl[0]>>2)&7)==3: frames.append(pl)  # SAPI3
            break
# reassemblage LAPDm : I-frames SAPI3, ordre N(S), champ info = L octets, jusqu'a M=0
ifr={}
for pl in frames:
    ctrl=pl[1]
    if ctrl & 1: continue            # garde les I-frames (bit0=0)
    ns=(ctrl>>1)&7; L=pl[2]>>2; M=(pl[2]>>1)&1
    ifr[ns]=(pl[3:3+L], M)
if not ifr:
    print("Aucune I-frame SAPI3 reassemblable."); sys.exit(1)
l3=b""; ns=0
while ns in ifr:
    info,M=ifr[ns]; l3+=info; ns+=1
    if not M: break
# SMS-CP -> RP-DATA -> SMS-DELIVER -> texte 7-bit
if l3[0]!=0x09: print("PD != SMS"); sys.exit(1)
rpdu=l3[3:3+l3[2]]
i=2; oal=rpdu[i]; i+=1; i+=oal; dal=rpdu[i]; i+=1; i+=dal; udl=rpdu[i]; i+=1
tp=rpdu[i:i+udl]
j=1; oa_len=tp[j]; j+=1; j+=1; j+=(oa_len+1)//2   # skip TP-OA
j+=1; j+=1; j+=7                                   # PID, DCS, SCTS(7)
ud_len=tp[j]; j+=1; ud=tp[j:]
def unpack7(data,n):
    out=[]; val=0; nb=0
    for by in data:
        val|=by<<nb; nb+=8
        while nb>=7 and len(out)<n:
            out.append(val&0x7f); val>>=7; nb-=7
    return out
G="@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
txt="".join(G[c] if c<len(G) else "?" for c in unpack7(ud,ud_len))
print("\n>>> TEXTE SMS DECODE : %r\n" % txt)
PY

echo "== termine =="
echo "  cfile    : $OUT"
echo "  sous-voie: -m $WIN_M -t $WIN_T -u $WIN_U"
echo ""
echo "  COMMANDE  (copiable) :"
echo "  grgsm_decode -m $WIN_M -t $WIN_T -u $WIN_U -a $ARFCN -s $SR -c $OUT $KEYARGS"
