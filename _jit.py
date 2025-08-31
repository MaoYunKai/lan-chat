import numba
import zlib
import hashlib
import struct
from numba import types
from numba.cpython import mathimpl
from numba.extending import intrinsic
import numpy as np
@numba.jit(nopython=True,fastmath=True,boundscheck=False)
def encrypt(y,z,k0,k1,k2,k3):
    delta=0x9e3779b9
    s=0xC6EF3720
    for i in range(32):
        y-=((z<<4)+k0)^(z+s)^((z>>5)+k1)
        y&=0xffffffff
        z-=((y<<4)+k2)^(y+s)^((y>>5)+k3)
        z&=0xffffffff
        s+=0x61C88647
        s&=0xffffffff
    return (y,z)
@intrinsic
def popcnt(typingctx, src):
    sig = types.uint64(types.uint64)

    def codegen(context, builder, signature, args):
        return mathimpl.call_fp_intrinsic(builder, "llvm.ctpop.i64", args)

    return sig, codegen
@numba.jit(nopython=True,fastmath=True,boundscheck=False)
def sdh_hash0(a,b,sk):#(data, 16_bytes_sec)->nv_chk
    q1=(a*1998244349+0x9e3779b9+(b<<6)+(b>>2))&0xffffffff
    q2=(b*1998244349+0x9e3779b9+(a<<6)+(a>>2))&0xffffffff
    m,n=encrypt(q1,q2,*sk)
    u,v=encrypt(0x9d2c5680,0xEDB88320,*sk)
    fchk0=fchk1=0
    fs=[(m+u)&0xffffffff,(n+v)&0xffffffff]
    bkey=37
    for i in range(16):
        fchk0,fchk1=encrypt(fs[0],fs[1],0xb5026f5a,fchk0,fchk1,0xa96619e9)
        fs[0]+=0x9e3779b9+(fchk0<<6)+(fchk1>>2)
        fs[1]+=0x9e3779b9+(fchk1<<6)+(fchk0>>2)
        fs[0]&=0xffffffff
        fs[1]&=0xffffffff
        bkey^=popcnt(fs[0])+popcnt(fs[1])
    nv_chk=encrypt(1566083941,19780503,fchk0,fs[1],fs[0],fchk1)
    nv_chk=nv_chk[0]*341873128712+nv_chk[1]*132897987541
    nv_chk += popcnt(nv_chk)*0x4d595df4d0f33173
    nv_chk&=0xffffffffffffffff
    nv_chk=(nv_chk+1442695040888963407)^(((m*341873128712+v*132897987541)^(u*314159+n*1000003))*6364136223846793005+0x9e3779b97f4a7c15+(nv_chk<<bkey)+(nv_chk>>(64-bkey)))
    nv_chk += popcnt(nv_chk)*0x4d595df4d0f33173
    nv_chk&=0xffffffffffffffff
    nv_chk=(nv_chk+1442695040888963407)^(((u*341873128712+n*132897987541)^(m*314159+v*1000003))*6364136223846793005+0x9e3779b97f4a7c15+(nv_chk<<bkey)+(nv_chk>>(64-bkey)))
    nv_chk += popcnt(nv_chk)*0x4d595df4d0f33173
    nv_chk&=0xffffffffffffffff
    nv_chk=(nv_chk^(nv_chk>>30))*0xbf58476d1ce4e5b9
    nv_chk&=0xffffffffffffffff
    nv_chk=(nv_chk^(nv_chk>>27))*0x94d049bb133111eb
    nv_chk&=0xffffffffffffffff
    nv_chk^=nv_chk>>31
    nv_chk&=0xffffffff
    return nv_chk
def sdh_hash(data,sec):#(data, 16_bytes_sec)->nv_chk
    a=zlib.crc32(hashlib.md5(data,usedforsecurity=False).digest()+sec)&0xffffffff
    b=zlib.adler32(hashlib.sha1(data).digest()+sec)&0xffffffff
    sk=struct.unpack(">IIII",sec)
    return sdh_hash0(a,b,sk)
@numba.jit(nopython=True,fastmath=True,boundscheck=False)
def calc_ber(rssi,noise_floor=-80):
    snr=rssi-noise_floor
    snr_linear=10**(snr/10)/4
    ber=0.5*erfc(sqrt(snr_linear))
    return ber
@numba.jit(nopython=True,fastmath=True,boundscheck=False)
def calc_expected_pktsize(rssi):
    ber = calc_ber(rssi)
    if not ber:
        return 1024
    s = round(20 / ber)
    s &= -8 # align
    return min(max(s,64),1280)
@numba.jit(nopython=True,fastmath=True,boundscheck=False)
def numba_fpow_32(x,y):
    result=1
    while y:
        if y&1:
            result = (result*x)&0xffffffff
        x=(x*x)&0xffffffff
        y>>=1
    return result
@numba.jit(nopython=True,fastmath=True,boundscheck=False)
def calcxyzyz(nv_chk,key,key2):
    x=((nv_chk^1000000007)*998244353)^((nv_chk^999999937)*0x9908b0df)
    x+=numba_fpow_32(37,popcnt(nv_chk))
    x&=0xffffffff
    y=((key&0xffffffff)+nv_chk)&0xffffffff
    z=((key>>32)+nv_chk)&0xffffffff
    chk2=numba_fpow_32(16807,key&0xffffffff)^numba_fpow_32(48271,key>>32)
    y2=((key2&0xffffffff)+chk2)&0xffffffff
    z2=((key2>>32)+chk2)&0xffffffff
    return x,y,z,y2,z2
@numba.jit((numba.uint32,)*4,nopython=True,fastmath=True,boundscheck=False)
def t64(k0,k1,k2,k3):
    y = np.uint64(0x4d595df4d0f33173)
    z = np.uint64(0xbf58476d1ce4e5b9)
    delta = np.uint64(0x9e3779b97f4a7c15)
    s = np.uint64(0x8dde6e5fd29f0540)
    for i in range(64):
        y -= ((z << 16) + k0) ^ (z + s) ^ ((z >> 17) + k1)
        y &= np.uint64(0xffffffffffffffff)
        z -= ((y << 16) + k2) ^ (y + s) ^ ((y >> 17) + k3)
        z &= np.uint64(0xffffffffffffffff)
        s += np.uint64(0x61c8864680b583eb)
        s &= np.uint64(0xffffffffffffffff)
    return (y, z)
def jit_cache_heating():
    sdh_hash(b'12312313213221231',b'1234567812345678')
    calcxyzyz(123123,114514191984,134134919348101)
    t64(1,4,3,2)
    return True

jit_cache_heating()

if __name__ == '__main__':
    with open(__file__,'r') as f:
        content=f.read()
    imports = content[:content.index("@")].strip()
    codes = content[content.index("@"):content.index("if __name__")].strip().replace("\n\n","\n")
    import base64
    encoded=base64.b85encode(zlib.compress(codes.encode('utf-8')))
    newcode = f"{imports}\nimport zlib,base64\nexec(zlib.decompress(base64.b85decode({encoded})).decode('utf-8'))"
    with open('jit.py','w') as f:
        f.write(newcode)
