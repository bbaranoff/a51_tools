#!/usr/bin/env python3
# gsmcode.py — codeur canal GSM 05.03 (SDCCH/SACCH/FACCH) : 23 octets -> 4 bursts de 114 bits
# Convention VALIDEE au bit pres contre GSMFrameCoder :
#     frame_to_bursts(frame, msb_first=False, invert=True, jvar=0)
# Vecteur de reference (doc science-integration.org, SI5) :
#   0000030349061d9f6d1810800000000000000000000000
#   -> Burst1 001000000001010000100000001100100010000011000000100000000110101000000000001011010001000000110100001000101001000110
#   (+ Burst2..4) : match exact 4/4.
#
# Chaine : Fire (224,184) + 4 tail bits + convolutif 1/2 (K=5) + entrelacement 4 bursts.

def bytes_to_bits(data23, msb_first=False):
    bits=[]
    for byte in data23:
        for i in range(8):
            bits.append((byte>>(7-i))&1 if msb_first else (byte>>i)&1)
    return bits  # 184

GPOLY=[40,26,23,17,3,0]   # g(D)=D^40+D^26+D^23+D^17+D^3+1
def fire_parity(info184, invert=True):
    reg=[0]*40
    for b in info184:
        fb=b^reg[39]
        nr=[0]*40
        for i in range(39,0,-1): nr[i]=reg[i-1]
        nr[0]=0
        if fb:
            for t in GPOLY:
                if t<40: nr[t]^=1
        reg=nr
    par=reg[::-1]
    if invert: par=[1-x for x in par]
    return par  # 40

def conv_encode(u):  # G0=1+D3+D4, G1=1+D+D3+D4
    out=[]
    for k in range(len(u)):
        g=lambda d: u[k-d] if k-d>=0 else 0
        out.append(g(0)^g(3)^g(4))
        out.append(g(0)^g(1)^g(3)^g(4))
    return out  # 456

def interleave_control(c456, jvar=0):
    bursts=[[0]*114 for _ in range(4)]
    for k in range(456):
        B=k%4
        j=2*((49*k)%57)+((k%8)//4) if jvar==0 else 2*((49*k)%57)+((k%4)//2)
        bursts[B][j]=c456[k]
    return bursts

def frame_to_bursts(data23, msb_first=False, invert=True, jvar=0):
    info=bytes_to_bits(data23, msb_first)
    par=fire_parity(info, invert)
    u=info+par+[0,0,0,0]
    return interleave_control(conv_encode(u), jvar)

def bstr(bits): return ''.join(map(str,bits))
def encode_hex(hex23):
    return [bstr(b) for b in frame_to_bursts(bytes.fromhex(hex23))]

if __name__=='__main__':
    ref=bytes.fromhex('0000030349061d9f6d1810800000000000000000000000')
    exp="001000000001010000100000001100100010000011000000100000000110101000000000001011010001000000110100001000101001000110"
    got=bstr(frame_to_bursts(ref)[0])
    print("auto-test vs GSMFrameCoder:", "OK" if got==exp else "ECHEC")
