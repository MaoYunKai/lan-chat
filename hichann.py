#Hidden Channel Support Library
from scapy.all import *
import zlib,hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers,SECP256R1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from jit import *
def sdh_hash(data,sec):#(data, 16_bytes_sec)->nv_chk
    a=zlib.crc32(hashlib.md5(data,usedforsecurity=False).digest()+sec)&0xffffffff
    b=zlib.adler32(hashlib.sha1(data).digest()+sec)&0xffffffff
    sk=struct.unpack(">IIII",sec)
    return sdh_hash0(a,b,*sk)
def find_parity_bits(n):
    """计算所需的校验位数量k"""
    k = 0
    while (1 << k) < n + k + 1:  # 2^k ≥ n + k + 1
        k += 1
    return k

def hamming_encode(data):
    """将二进制数据编码为汉明码"""
    # 确保输入是二进制列表（仅包含0和1）
    if not all(bit in (0, 1) for bit in data):
        raise ValueError("数据必须是二进制列表（仅包含0和1）")
    
    n = len(data)
    k = find_parity_bits(n)
    m = n + k  # 编码后的总长度
    code = [0] * (m + 1)  # 使用1-based索引（位置0未使用）
    
    # 填充数据位到非校验位位置（非2的幂次方位置）
    data_index = 0
    for pos in range(1, m + 1):
        if (pos & (pos - 1)) != 0:  # 不是2的幂次方（校验位位置特征）
            code[pos] = data[data_index]
            data_index += 1
    
    # 计算每个校验位的值（覆盖范围内数据位的异或）
    for i in range(k):
        parity_pos = 1 << i  # 校验位位置：2^0, 2^1, 2^2...
        parity_value = 0
        # 计算所有被该校验位覆盖的位置的异或
        for pos in range(1, m + 1):
            if pos & parity_pos:  # 位置的二进制包含当前校验位的位
                parity_value ^= code[pos]
        code[parity_pos] = parity_value
    
    return code[1:]  # 返回1-based到m的部分（去掉位置0）

def hamming_decode(code):
    """解码汉明码，检测并纠正错误，返回原始数据"""
    m = len(code)
    if m == 0:
        return [], 0
    
    # 确定校验位数量k
    k = 0
    while (1 << k) <= m:
        k += 1
    k -= 1  # 调整到正确的数量
    
    # 计算错误位置
    error_pos = 0
    for i in range(k):
        parity_pos = 1 << i
        parity_value = 0
        # 重新计算校验位
        for pos in range(m):
            actual_pos = pos + 1  # 转换为1-based索引
            if actual_pos & parity_pos:
                parity_value ^= code[pos]
        # 如果校验位不匹配，记录错误位置
        if parity_value != 0:
            error_pos += parity_pos
    
    # 纠正错误（如果有）
    if error_pos != 0 and error_pos <= m:
        # 转换为0-based索引并翻转位
        code[error_pos - 1] ^= 1
    
    # 提取原始数据位（排除校验位位置）
    data = []
    for pos in range(m):
        actual_pos = pos + 1
        if (actual_pos & (actual_pos - 1)) != 0:  # 非校验位位置
            data.append(code[pos])
    
    return data, error_pos
def iphc(chat_id):
    d=os.urandom(random.randint(20,50))
    cc=zlib.crc32(d)&0xffffffff
    h1=(((chat_id^34421)*51719+cc>>16)&0xffff)^44879
    h2=(((chat_id^58309)*44357+cc&0xffff)&0xffff)^52359
    q=zlib.adler32(d)&0xffffffff
    q^=cc + 0x9e3779b9 + (q << 6) + (q >> 2)
    q^=h1 + 0x9e3779b9 + (q << 6) + (q >> 2)
    q^=h1 + 0x9e3779b9 + (q << 6) + (q >> 2)
    q&=0xffff
    return Ether(src=conf.iface.mac,dst="ff:ff:ff:ff:ff:ff")/\
                IP(src=conf.iface.ip,id=(chat_id+q)&0xffff,dst="255.255.255.255")/\
                UDP(sport=h1,dport=h2)/\
                d
def check_iphc(pkt):
    d=pkt[Raw].load
    h1=pkt[UDP].sport
    h2=pkt[UDP].dport
    cc=zlib.crc32(d)&0xffffffff
    q=zlib.adler32(d)&0xffffffff
    q^=cc + 0x9e3779b9 + (q << 6) + (q >> 2)
    q^=h1 + 0x9e3779b9 + (q << 6) + (q >> 2)
    q^=h1 + 0x9e3779b9 + (q << 6) + (q >> 2)
    q&=0xffff
    chat_id=(pkt[IP].id-q)&0xffff
    h1_=(((chat_id^34421)*51719+cc>>16)&0xffff)^44879
    h2_=(((chat_id^58309)*44357+cc&0xffff)&0xffff)^52359
    if h1==h1_ and h2==h2_:
        return chat_id
    else:
        return None
def ip_hidden_writer(pkt,int32v):
    d=bin(int32v)[2:].rjust(32,'0')
    encoded=hamming_encode(list(map(int,d)))
    #38 bit
    dd=int(''.join(map(str,encoded)),2)
    #id(16), frag(13), ttl(3), tos(6)
    pkt[IP].id = (dd>>22)&0xffff
    pkt[IP].frag = (dd>>9)&0x1fff
    pkt[IP].ttl = (1+((dd>>6)&7))<<4
    pkt[IP].tos = (dd&0x3f)<<2
def ip_hidden_reader(pkt):
    a=pkt[IP].id<<22
    b=pkt[IP].frag<<9
    c=(((pkt[IP].ttl+15)>>4)-1)<<6
    d=pkt[IP].tos>>2
    dd=a+b+c+d
    ds=bin(dd)[2:].rjust(38,'0')
    d,e=hamming_decode(list(map(int,ds)))
    #print(e)
    return int(''.join(map(str,d)),2)
def safe_udp_hidden_writer(int64v):
    d=os.urandom(random.randint(20,50))
    a=zlib.crc32(d)&0xffffffff
    b=zlib.adler32(d)&0xffffffff
    p=a+0x9e3779b9+(b<<6)+(b>>2)
    q=b+0x9e3779b9+(a<<6)+(a>>2)
    l = (int64v^q)&0xffffffff
    pkt=Ether(src=conf.iface.mac,dst="ff:ff:ff:ff:ff:ff")/\
         IP(src=conf.iface.ip,dst="255.255.255.255")/\
         UDP(sport=l>>16,dport=l&0xffff)/\
         d
    ip_hidden_writer(pkt,((int64v>>32)^p)&0xffffffff)
    return pkt
def safe_udp_hidden_reader(pkt):
    if isinstance(pkt[IP].payload,Raw):
        pkt[IP].payload=UDP(pkt[IP].payload.load)
    d=pkt[Raw].load
    a=zlib.crc32(d)&0xffffffff
    b=zlib.adler32(d)&0xffffffff
    p=a+0x9e3779b9+(b<<6)+(b>>2)
    q=b+0x9e3779b9+(a<<6)+(a>>2)
    dl=((pkt[UDP].sport<<16)|pkt[UDP].dport)^(q&0xffffffff)
    dh=ip_hidden_reader(pkt)^(p&0xffffffff)
    return (dh<<32)|dl
def ec_public_number_pack(k):
    return k.x.to_bytes(32,'big')+k.y.to_bytes(32,'big')
def ec_public_number_load(d):
    return EllipticCurvePublicNumbers(int.from_bytes(d[:32],'big'),int.from_bytes(d[32:],'big'),SECP256R1())
def rsa_public_number_pack(n):
    return n.n.to_bytes(256,'big')
def rsa_public_number_load(d):
    return RSAPublicNumbers(65537,int.from_bytes(d,'big'))
def safe_data_hide(mac_tgt,ip_tgt,key,data,key2=1145141919810):
    ippkt=IP(dst=ip_tgt,flags='DF')
    sec=os.urandom(16)
    nv_chk = sdh_hash(data,sec)
    #print(f"send hash('{data[:10]}'...,size={len(data)}) = {nv_chk}")
    x,y,z,y2,z2=calcxyzyz(nv_chk,key,key2)
    ippkt.id=x>>16
    apkt=AH()
    apkt.reserved=x&0xffff
    apkt.spi=y2
    apkt.seq=z2
    apkt.payloadlen=5
    apkt.icv=sec
    apkt.nh='esp'
    return Ether(dst=mac_tgt)/ippkt/apkt/ESP(spi=y,seq=z,data=data)
def safe_data_extract(pkt):
    sec=pkt[AH].icv
    if isinstance(pkt[AH].payload,(Raw)):
        pkt[AH].payload=ESP(pkt[AH].payload.load)
    data=pkt[ESP].data
    nv_chk = sdh_hash(data,sec)
    x=((nv_chk^1000000007)*998244353)^((nv_chk^999999937)*0x9908b0df)
    x+=pow(37,nv_chk.bit_count(),4294967296)
    x&=0xffffffff
    ippkt=pkt[IP]
    new_x = (ippkt.id<<16)|pkt[AH].reserved
    #print(f"recv hash('{data[:10]}'...,size={len(data)}) = {nv_chk}")
    if x != new_x:
        print("Wrond Check!",f'expected {x} got {new_x}')
        return None
    key=(pkt[ESP].spi-nv_chk)&0xffffffff
    key_hi=(pkt[ESP].seq-nv_chk)&0xffffffff
    chk2=pow(16807,key,4294967296)^pow(48271,key_hi,4294967296)
    key2_lo=(pkt[AH].spi-chk2)&0xffffffff
    key2_hi=(pkt[AH].seq-chk2)&0xffffffff
    return (key_hi<<32)|key,data,(key2_hi<<32)|key2_lo
class SafeEspSocket():
    def __init__(self,ip,packetreceiver,tgt_mac_getter=getmacbyip,tgt_mac_setter=None):
        self.__dest = ip
        self.__mac_tgt = tgt_mac_getter
        self.__mac_s = tgt_mac_setter
        self.__recv = packetreceiver
        self.__sock = conf.iface.l2socket()(type=ETH_P_ALL,promisc=True)
        self.__sniffer = AsyncSniffer(filter='host '+ip,
                                      opened_socket = self.__sock,
                                      prn = self.__onsniff,
                                      store=False)
        self.__sniffer.start()
    def close(self):
        self.__sniffer.stop()
    def __fill(self,data):
        p = data
        if len(p)<1300:
            p += os.urandom(1300-len(p))
        sec = b"secure size pack"
        h = sdh_hash(p,sec)
        result=struct.pack(">I",len(data)^h)+p
        return result
    def __unfill(self,data):
        p=data[4:]
        sec = b"secure size pack"
        h = sdh_hash(p,sec)
        realsize=struct.unpack(">I",data[:4])[0]^h
        return data[4:4+realsize]
    def send_raw(self,data):
        if isinstance(data,Packet):
            #data.show()
            data=bytes(data)
        key=os.urandom(16)
        iv=os.urandom(12)
        e=AESGCM(key)
        mi=self.__fill(iv+e.encrypt(iv,data,None))
        k1,k2=struct.unpack(">QQ",key)
        p=safe_data_hide(self.__mac_tgt(self.__dest), self.__dest, k1, mi, key2=k2)
        sendp(p,socket=self.__sock,verbose=False)
    def __onsniff(self,pkt):
        try:
            if not AH in pkt:
                return
            if pkt[IP].src != self.__dest or pkt[IP].dst != conf.iface.ip:
                return
            try:
                d=safe_data_extract(pkt)
            except:
                d=None
            if not d:
                print("A packet is abandoned")
                return
            #print("Received one packet")
            k,mi,k2=d
            mi=self.__unfill(mi)
            hkey=struct.pack(">QQ",k,k2)
            e=AESGCM(hkey)
            if self.__mac_s:
                self.__mac_s(self.__dest,pkt[Ether].src)
            self.__recv(e.decrypt(mi[:12],mi[12:],None))
        except:
            import traceback
            traceback.print_exc()
# 测试示例
if __name__ == "__main__":
    '''for i in range(10):
        a=Ether()/IP()/UDP()
        num=random.randint(0,4294967295)
        print(f"Writing {num}")
        ip_hidden_writer(a,num)
        a.show2()
        assert ip_hidden_reader(a)==num'''
