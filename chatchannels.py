import traceback
import hichann,lzma
from bufq import ThreadSafeBuffer
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import ec,rsa,padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time,pickle,struct,os,base64,io,queue
import zlib,pyperclip
import argon2
class IcmpMessageData(Packet):
    name = "Icmp Message Data "
    fields_desc = [
        FieldLenField('len',None,length_of='data'),
        StrLenField('data','',length_from=lambda pkt:pkt.len),
        XShortField('seq',0),
        IntField('chksum',None)
    ]
    def self_build(self):
        if self.chksum is None:
            self.chksum = zlib.adler32(self.data)
        return super().self_build()
    def verify_message(self):
        if self.chksum != zlib.adler32(self.data):
            raise ValueError("Bad IcmpMessageData")
class IcmpMessage(Packet):
    name = "Icmp Message "
    fields_desc = [
        ByteEnumField('type', 4,
                     {0:'wakeup',1:'wakeup_established',
                      2:'established',3:'heartbeat',
                      4:'message',5:'acknowledge'}),
        PacketListField('message',None,IcmpMessageData,count_from=lambda pkt:pkt.type in [4,5])
    ]
    def self_build(self):
        return super().self_build()
    def verify_message(self):
        if self.type > 4:
            raise ValueError("Bad type")
        if self.type==4:
            self.message[0].verify_message()
bind_layers(ICMP,IcmpMessage,type=8,id=709)
class ChatConfig(Packet):
    name = 'Chat Configure '
    fields_desc = [
        XShortField('chat_id', None),
        Emph(SourceIPField('ip_addr')),
        Emph(SourceMACField('mac_addr'))
    ]
bind_layers(ARP,ChatConfig,op=1,pdst='67.72.65.84')
class IcmpSock():
    def __init__(self,ip,start=True,dmac_func=getmacbyip,mac_set_func=None):
        self.__dest = ip
        self.__macf = dmac_func
        self.__macsf = mac_set_func
        self._seq = 0
        self._ack = 0
        self.__status = 'U'
        self.__recvbuf = ThreadSafeBuffer(65536)
        self.__exec = ThreadPoolExecutor(1)
        self.__wakeup_signal = queue.Queue()
        self.__establ_signal = queue.Queue()
        self.__heartbeat_signal = queue.Queue()
        self.__sndrcv_signal = queue.Queue()
        self.__l = threading.Lock()
        self.__receive_signals = conf.netcache.new_cache(f"icmpsock_recv_sig_{id(self)}", 5)
        self.__esps = hichann.SafeEspSocket(ip,self.__recv_pkt,dmac_func,mac_set_func)
        if start:
            #print("sending WAKEUP")
            #self.__sniffer.start()
            self.__connect()
        self.__closed = False
        self.__alive = True
    def start_heartbeat(self):
        msg = IcmpMessage(type='heartbeat')
        while not self.__closed:
            self.__esps.send_raw(msg)
            time.sleep(1)
    def check_heartbeat(self):
        while not self.__closed:
            self.__heartbeat_signal.get(timeout=10)
    @property
    def remote_addr(self):
        return self.__dest
    @property
    def isalive(self):
        try:
            self.__heartbeat_signal.get(timeout=1.5)
        except:
            return False
        else:
            self.__heartbeat_signal.put(0)
            return True
    def __connect(self):
        # A->Wakeup->B (A:U,B:?)
        # B start (A:U,B:U)
        # B->Wakeup->A (A:W,B:U)
        # A->Wakeup+Establish->B (A:W,B:W)
        # B->Wakeup+Establish->A (A:E,B:W)
        for i in range(10):
            self.__esps.send_raw(IcmpMessage(type='wakeup'))
            try:
                self.__wakeup_signal.get(timeout=0.5)
            except:
                pass
            else:
                for j in range(10):
                    self.__esps.send_raw(IcmpMessage(type='wakeup_established'))
                    try:
                        self.__establ_signal.get(timeout=0.5)
                    except:
                        pass
                    else:
                        self.__esps.send_raw(IcmpMessage(type='established'))
                        return
                raise IOError("Connect failed")
        raise IOError("Connect failed")
    def _start(self):
        self.__sniffer.start()
    def __send0(self,msg):
        s=self._seq&0xffff
        self._seq += 1
        p = IcmpMessage(message=IcmpMessageData(data=msg,seq=s))
        rsig = queue.Queue()
        self.__receive_signals[s,]=rsig
        try:
            for i in range(5):
                self.__esps.send_raw(p)
                try:
                    rsig.get(timeout=1)
                except:
                    pass
                else:
                    self.__heartbeat_signal.put(1)
                    return 1
            raise IOError("Send failed")
        finally:
            del self.__receive_signals[s,]
    def __send(self,msg):
        b=io.BytesIO(msg)
        with self.__l:
            while (f:=b.read(1000)):
                self.__send0(f)
    def sendMsg(self,msg):
        #print("Sending:", msg[:10])
        self.__send(struct.pack(">I",len(msg))+msg)
    def close(self):
        if not self.__closed:
            self.__esps.close()
            self.__exec.shutdown()
            self.__recvbuf.close()
            self.__closed=True
    @property
    def closed(self):
        return self.__closed
    def __recv_pkt(self,data):
        msg = IcmpMessage(data)
        #msg.show()
        if msg.type == 4:
            self.__heartbeat_signal.put(1) 
            self.__exec.submit(self.__process_pkts,msg)
        elif msg.type == 0 and self.__status == 'U':
            self.__status = 'W'
            self.__wakeup_signal.put(1)
        elif msg.type == 1:
            if self.__status == 'U':
                self.__status = 'W'
                self.__wakeup_signal.put(1)
            elif self.__status == 'W':
                self.__status = 'E'
                self.__establ_signal.put(1)
        elif msg.type == 2 and self.__status == 'W':
            self.__status = 'E'
            self.__establ_signal.put(1)
        elif msg.type == 3:
            self.__heartbeat_signal.put(1)
        elif msg.type == 5:
            #print('received ACK',msg.message[0].seq)
            try:
                self.__receive_signals[msg.message[0].seq,].put(0)
            except KeyError:
                pass
    def __process_pkts(self,data):
        sq=data.message[0].seq
        self.__esps.send_raw(IcmpMessage(type='acknowledge',message=IcmpMessageData(data=b'ack',seq=sq)))
        if sq < self._ack:
            return
        self._ack = (sq+1)&0xffff
        self.__recvbuf.write(data.message[0].data)
    def __read0(self,length):
        data=b''
        while length:
            d = self.__recvbuf.read(length)
            if not d:
                return data
            data+=d
            length-=len(d)
        return data
    def recvMsg(self):
        data = self.__recvbuf.read(4)
        if len(data)<4:
            raise IOError("Channel closed")
        size,=struct.unpack(">I",data)
        msg = self.__read0(size)
        if len(msg)<size:
            raise IOError("Channel closed")
        #print("Receiving ",msg[:10])
        return msg
class IcmpListenSock():
    def __init__(self):
        self.__conn = queue.Queue()
        self.__sniffer = AsyncSniffer(prn=self.__recv, filter='icmp', store=False)
        self.__sniffer.start()
        self.__conns = {}
    def __recv(self,pkt):
        if ICMP in pkt:
            if pkt[ICMP].type == 8:
                addr = pkt[IP].src
                if addr in self.__conns:
                    if self.__conns[addr].closed:
                        a=IcmpSock(addr)
                        self.__conn.put(a)
                        self.__conns[addr]=a
                else:
                    a=IcmpSock(addr)
                    self.__conn.put(a)
                    self.__conns[addr]=a
    def accept(self):
        s=self.__conn.get()
        s._start()
        return s
    def close(self):
        self.__sniffer.stop()
class KeyExchange():
    def __init__(self):
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._rkey = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self._hasher = argon2.PasswordHasher(memory_cost=128*1024)
        self.timesec_value = 0
    def __comp(self,data):
        a=zlib.compressobj(level=9,wbits=-15,memLevel=9)
        return a.compress(data)+a.flush()
    def __decomp(self,data):
        return zlib.decompress(data,wbits=-15)
    def keyToBytes(self):
        return hichann.ec_public_number_pack(self._key.public_key().public_numbers())
    def swapKey(self,data):
        self._sk = AESGCM(self._key.exchange(ec.ECDH(),hichann.ec_public_number_load(data).public_key()))
    def newKeyToBytes(self):
        iv=os.urandom(16)
        data = hichann.rsa_public_number_pack(self._rkey.public_key().public_numbers())
        enc = self._sk.encrypt(iv,data,None)
        return iv+enc
    def decodeKeyToBytes(self,data):
        dec = self._sk.decrypt(data[:16],data[16:],None)
        self._rrkey = hichann.rsa_public_number_load(dec).public_key()
    def encryptData(self,data):
        key=os.urandom(32)
        iv=os.urandom(12)
        timesec=struct.pack(">Q",int(time.time()*1000))
        aes_key=self._hasher.hash(key+timesec,salt=iv).split("$")[-1]
        aes_key += '='*((-len(aes_key))&3)
        a=AESGCM(base64.b64decode(aes_key))
        e=a.encrypt(iv,data,None)
        ek=self._sk.encrypt(iv,self._rrkey.encrypt(key,padding.PKCS1v15()),None)
        return timesec+iv+struct.pack(">I",len(e))+e+ek
    def decryptData(self,data):
        timesec = data[:8]
        t = struct.unpack(">Q",timesec)[0]
        if t <= self.timesec_value:
            raise ValueError("The message is expired")
        self.timesec_value=t
        iv = data[8:20]
        data_size, = struct.unpack(">I",data[20:24])
        e = data[24:24+data_size]
        ek = data[24+data_size:]
        key = self._rkey.decrypt(self._sk.decrypt(iv,ek,None),padding.PKCS1v15())
        aes_key=self._hasher.hash(key+timesec,salt=iv).split("$")[-1]
        aes_key += '='*((-len(aes_key))&3)
        a=AESGCM(base64.b64decode(aes_key))
        return a.decrypt(iv,e,None)
class P2PData(Packet):
    #min size 19
    name="P2P Data"
    fields_desc=[
        IntField('filenamechksum',None),
        FieldLenField("conf_len", None, count_of="confirmed", fmt='B'),
        FieldListField("confirmed", [], IPField('','127.0.0.1'), count_from=lambda pkt:pkt.conf_len),
        XIntField('offset',0),
        FieldLenField('len',None,length_of='data'),
        StrLenField('data','',length_from=lambda pkt:pkt.len),
        IntField('chksum',None)
    ]
    def self_build(self):
        if self.chksum is None:
            self.chksum = zlib.crc32(self.data)
        return super().self_build()
class P2PFileHeader(Packet):
    name="P2P Header"
    fields_desc=[
        FieldLenField('namelen',None,length_of='filename'),
        StrLenField('filename','',length_from=lambda pkt:pkt.namelen),
        XIntField('filesize',0),
        XIntField("realsize",0),
        IntField('filenamechksum',None)
    ]
    def self_build(self):
        if self.filenamechksum is None:
            self.filenamechksum = zlib.adler32(self.filename)
        return super().self_build()
class SecureIcmpSocket():
    def __init__(self,s):
        self.__s = s
        self.__e = KeyExchange()
        self.__l = threading.Lock()
    def handshake(self):
        self.__s.sendMsg(self.__e.keyToBytes())
        self.__e.swapKey(self.__s.recvMsg())
        self.__s.sendMsg(self.__e.newKeyToBytes())
        self.__e.decodeKeyToBytes(self.__s.recvMsg())
    def send(self,data):
        with self.__l:
            self.__s.sendMsg(self.__e.encryptData(data))
    def recv(self):
        return self.__e.decryptData(self.__s.recvMsg())
    def close(self):
        self.__s.close()
    @property
    def closed(self):
        return self.__s.closed
    @property
    def remote_addr(self):
        return self.__s.remote_addr
    @property
    def isalive(self):
        return self.__s.isalive
class P2P_Manager():
    def __init__(self,ip_provider,data_sender,header_sender,ip=conf.iface.ip):
        self.__ip_prov = ip_provider
        self.__send_data = data_sender
        self.__send_hdr = header_sender
        self.__ip = ip
        class _File():
            def __init__(self,filename,size,rsize):
                self.__name = filename
                self.__data = bytearray(size)
                self.__received = 0
                self.__sizefactor = rsize/size
                self.__ssss = rsize
            def _receive(self,off,dat):
                self.__received += len(dat)
                self.__data[off:off+len(dat)]=dat
            @property
            def download_size(self):
                return round(self.__received*self.__sizefactor)
            @property
            def total_size(self):
                return self.__ssss
            @property
            def data(self):
                if self.download_size < self.total_size:
                    raise IOError("file is truncated!")
                return lzma.decompress(bytes(self.__data),2)
            @property
            def name(self):
                return self.__name
        self.__ftype = _File
        self.__files = {}
        self.__rnd = random.Random()
    def onReceiveData(self,data):
        pkt = P2PData(data)
        ips = self.__ip_prov()
        newcfm = pkt.confirmed+[self.__ip]
        addrs = tuple(ips-newcfm)
        if addrs:
            newIp=self.__rnd.choice(addrs)
            newPkt=P2PData(filenamechksum=pkt.filenamechksum,
                           confirmed=newcfm,
                           offset=pkt.offset,
                           data=pkt.data)
            self.__send_data(newIp,bytes(newPkt))
        print(f"file {pkt.filenamechksum} received chunk {pkt.offset},size={len(pkt.data)}")
        self.__files[pkt.filenamechksum]._receive(pkt.offset,pkt.data)
    def onReceiveHeader(self,data):
        hdr = P2PFileHeader(data)
        f=self.__ftype(hdr.filename.decode(),hdr.filesize,hdr.realsize)
        print(f"file {hdr.filenamechksum} received name {hdr.filename}")
        self.__files[hdr.filenamechksum]=f
        return f
    def sendFile(self,data,filename,p_rec=None):
        realsize=len(data)
        data = lzma.compress(data,2)
        szfactor=realsize/len(data)
        filename = filename.encode()
        hdr = P2PFileHeader(filename=filename,realsize=realsize,filesize=len(data))
        hdr = P2PFileHeader(bytes(hdr))
        chk = hdr.filenamechksum
        ips = list(self.__ip_prov()-{self.__ip})
        if not ips:
            if p_rec is not None:
                p_rec(realsize)
            return
        for ip in ips:
            self.__send_hdr(ip,bytes(hdr))
        ip_it=itertools.chain.from_iterable(map(lambda x:[random.shuffle(x),x][1],itertools.repeat(ips)))
        chunk_size = min(max((len(data)+len(ips)-1)//len(ips),200),60000)
        fd = io.BytesIO(data)
        while (d:=fd.read(chunk_size)):
            self.__send_data(next(ip_it),
                             bytes(P2PData(filenamechksum=chk,
                                           confirmed=[self.__ip],
                                           offset=fd.tell()-len(d),
                                           data=d)))
            if p_rec is not None:
                p_rec(round(fd.tell()*szfactor))
class ChatRoomNetwork():
    def __init__(self, ident, uhdl, rhdl):
        self.__id = ident
        self.__ip = conf.iface.ip
        self.__usrhdl = uhdl
        self.__chkrun = rhdl
        self.__sock=conf.iface.l2socket()(type=ETH_P_ALL,promisc=True)
        self.__iptomac_cache = conf.netcache.new_cache(f"chat_iptab_cache_{ident}", 5)
        self.__sniffer = AsyncSniffer(prn=self.__sniff_broadcast, filter='udp and host 255.255.255.255', opened_socket = self.__sock, store=False)
        self.__sniffer.start()
        self.__sbc = threading.Thread(target=self.__send_broadcasts)
        self.__sbc.start()
    @property
    def ip_addr(self):
        return self.__ip
    @property
    def __running(self):
        return self.__chkrun()
    def __send_broadcasts(self):
        def h():
            while self.__running:
                yield hichann.iphc(self.__id)
        send(h(),inter=1,verbose=False,socket=self.__sock)
    def __sniff_broadcast(self,pkt):
        if IP in pkt and UDP in pkt and Raw in pkt:
            if pkt[IP].src != self.__ip:
                cid = hichann.check_iphc(pkt)
                if cid is not None and cid == self.__id:
                    self.__iptomac_cache[pkt[IP].src]=pkt[Ether].src
                    self.__usrhdl(pkt[IP].src)
    def __mactable_get(self,ipaddr):
        try:
            return self.__iptomac_cache[ipaddr]
        except KeyError:
            new_mac_addr = getmacbyip(ipaddr)
            if not new_mac_addr:
                return 'ff:ff:ff:ff:ff:ff'
            self.__iptomac_cache[ipaddr]=new_mac_addr
            return new_mac_addr
    def __mactable_update(self,ipaddr,macaddr):
        self.__iptomac_cache[ipaddr]=macaddr
    def create_sock(self,ipaddr):
        return IcmpSock(ipaddr,dmac_func=self.__mactable_get,mac_set_func=self.__mactable_update)
    def stop(self):
        self.__sniffer.stop()
        self.__sbc.join()
        self.__sock.close()
class ChatRoom():
    def __init__(self,chatroomId,networkclass=ChatRoomNetwork):
        self.__id = chatroomId
        self.__running = True
        self.__users = {}
        self.__inactive_users = conf.netcache.new_cache(f"chat_inactive_users_{chatroomId}", 60)
        #filter = 'arp or icmp'???
        self.__pol = ThreadPoolExecutor(5)
        self.__msgs = queue.Queue()
        self.__nw_lock = threading.Lock()
        self.__nw = networkclass(self.__id, self.__usrhdl, lambda:self.__running)
        self.__pm = P2P_Manager(lambda:self.__users.keys(),
                                lambda ip,data:self.__senddata(1,self.__get_user(ip),data),
                                lambda ip,data:self.__senddata(2,self.__get_user(ip),data),
                                ip=self.__nw.ip_addr)
    def __get_user(self,ip):
        return self.__users.get(ip,self.__inactive_users.get(ip))
    def hiddenBroadcast(self,data):
        #ARP hidden broadcast
        # 67.72.65.84 'CHAT'
        return Ether(dst=ETHER_BROADCAST) / ARP() / data
    def __usrhdl(self,ip):
        self.__pol.submit(self.__handle_new_user,ip)
    def __handle_new_user(self,p):
        if p in self.__users:
            return
        t=self.__inactive_users.get(p)
        if t is not None and t.isalive:
            self.__users[p]=t
            try:
                del self.__inactive_users[p]
            except:
                pass
            return
        with self.__nw_lock:
            if p in self.__users:
                return
            self.__msgs.put(("System",f"ip {p} connecting"))
            try:
                isock = self.__nw.create_sock(p)
                threading.Thread(target=isock.start_heartbeat).start()
                threading.Thread(target=self.__socket_guard_1, args=(isock,)).start()
                sis = SecureIcmpSocket(isock)
                sis.handshake()
                self.__users[p]=sis
                if p in self.__inactive_users:
                    try:
                        self.__inactive_users[p].close()
                        del self.__inactive_users[p]
                    except:
                        pass
                threading.Thread(target=self.__consume_thread,args=(p,sis)).start()
            except:
                self.__msgs.put(("System",traceback.format_exc()))
    def __process_msg(self,msg):
        typ=msg[0]
        if typ==0:
            #normal message
            return lzma.decompress(msg[1:],2).decode()
        elif typ==1:
            #p2p data
            self.__pm.onReceiveData(msg[1:])
        elif typ==2:
            #p2p header
            return self.__pm.onReceiveHeader(msg[1:])
    def __consume_thread(self,ip,sis):
        while self.__running:
            try:
                p = self.__process_msg(sis.recv())
                if p is not None:
                    if sis.remote_addr not in self.__users:
                        try:
                            del self.__inactive_users[sis.remote_addr]
                        except:
                            pass
                        self.__users[sis.remote_addr]=sis
                    self.__msgs.put((ip,p))
            except:
                try:
                    del self.__users[sis.remote_addr]
                except:
                    pass
                self.__inactive_users[sis.remote_addr]=sis
                if sis.closed:
                    break
                self.__msgs.put(("System",traceback.format_exc()))
    def __socket_guard_1(self,u):
        try:
            u.check_heartbeat()
        except:
            try:
                del self.__users[u.remote_addr]
            except:
                pass
            self.__inactive_users[u.remote_addr]=u
            if u.closed:
                return
            self.__msgs.put(("System",f'{u.remote_addr}已离线'))
    def __send_msg(self,typ,u,msg):
        try:
            u.send(bytes([typ])+msg)
        except:
            self.__msgs.put(("System",traceback.format_exc()))
            try:
                del self.__users[u.remote_addr]
            except:
                pass
            self.__inactive_users[u.remote_addr]=u
    def __senddata(self,typ,u,msg):
        self.__pol.submit(self.__send_msg,typ,u,msg)
    def send(self, msg):
        z = lzma.compress(msg.encode(),2)
        for u in self.__users.values():
            self.__senddata(0,u,z)
    def sendfile(self, filename, data):
        class _Progress():
            def __init__(self):
                self.__p=0
            def __call__(self):
                return self.__p
            def set(self,p):
                self.__p=p
        p=_Progress()
        threading.Thread(target=self.__pm.sendFile,args=(data,filename,p.set)).start()
        return p
    def recv(self):
        return self.__msgs.get()
    @property
    def user_cnt(self):
        return len(self.__users)+1
    def quit(self):
        self.__running=False
        self.__nw.stop()
        self.__pol.shutdown()
        for u in self.__users.values():
            u.close()
        for u in self.__inactive_users.values():
            u.close()
