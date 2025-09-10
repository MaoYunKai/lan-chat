#Wireless Transport Support Library
from scapy.all import *
from math import erfc,sqrt
from wlhlp import NmCapture,wl_sendp,pack_wl_data,unpack_wl_data,setchannel2,override_faces
from bufq import ThreadSafeBuffer
import functools, weakref, traceback
from hichann import sdh_hash, rng_encrypt, rng_decrypt
from concurrent.futures import ThreadPoolExecutor
from jit import *
class PacketSizeMgr():
    __slots__=('__s','__dict__','__weakref__')
    def __init__(self):
        self.__s = 1280
    def getsize(self):
        return self.__s
    def __repr__(self):
        return "Size="+str(self.__s)
    def onretransmit(self):
        self.__s >>= 1
        self.__s &= -8
        self.__s = max(self.__s,64)
    def onreceive(self,rssi):
        if not rssi:
            return
        expc = calc_expected_pktsize(rssi)
        if self.__s < expc:
            self.__s = (self.__s*5+expc) // 6
            self.__s &= -8
        elif expc < (self.__s>>1):
            self.__s = (self.__s*3+expc) >> 2
            self.__s += 7
            self.__s &= -8
@functools.lru_cache()
class WirelessLocker():
    __slots__=('__ref','__l','__chann','__dict__','__weakref__')
    def __init__(self, channel):
        override_faces()
        self.__ref = 0
        self.__l = threading.Lock()
        self.__chann = channel
    def lock(self):
        print('wl lock()')
        with self.__l:
            if self.__ref<=0:
                conf.iface.setmonitor(True)
                setchannel2(conf.iface,2,self.__chann)
            self.__ref += 1
    def unlock(self):
        print('wl unlock()')
        with self.__l:
            self.__ref -= 1
            if self.__ref<=0:
                conf.iface.setmonitor(False)
    def __enter__(self):
        self.lock()
        return self
    def __exit__(self,*a,**k):
        self.unlock()
    def __del__(self,*a,**k):
        conf.iface.setmonitor(False)
class Wireless_packet(Packet):
    #__slots__=('datakey','data','size','id','flags','frag')
    name='Wireless Transport Message'
    fields_desc=[
        XStrFixedLenField('datakey', None, length=16),
        StrField('data',None,remain=8),
        ShortField("size",0),#the original size
        IntField("id",0),
        FlagsField('flags',1,3,['data','acknowledge','retransmission']),
        BitField('frag',0,13)
    ]
    def dissect(self,p):
        try:
            aaa,=struct.unpack(">Q",p[-8:])
            k=p[:16]
            d = rng_decrypt(p[16:-8],k)
            h = sdh_hash(d,k)
            aaa ^= h*2718281
            p=k+d+struct.pack(">Q",aaa)
            return super().dissect(p)
        except:
            super().dissect(p)
            self.data = b'<undecrypted data>'
            self.id=0xffffffff
            self.flags=0 # no flags, prevent WirelessTransportBase to retrieve data
    def post_build(self,p,pay):
        aaa, = struct.unpack(">Q",p[-8:])
        k = os.urandom(16)
        h = sdh_hash(p[16:-8],k)
        aaa ^= h*2718281
        fi = struct.pack(">Q",aaa)
        enc = rng_encrypt(p[16:-8],k)
        return k+enc+fi
class WirelessTransportBase():
    __slots__=(
        '__wlocker',
        '__phdl',
        '__s_sig',
        '__dq',
        '__sock',
        '__tq',
        '__snf',
        '__pkt_size',
        '__id',
        '__dict__',
        '__weakref__'
    )
    def __init__(self,channel=6):
        self.__wlocker = WirelessLocker(channel)
        self.__wlocker.lock()
        class _datafq():
            def __init__(self,s,size):
                self.sdr = s
                self.__size=size
                self.__buf = bytearray(self.__size)
                self.__bitm = [False]*self.__size
            def onrecv(self,pkt):
                off = pkt.frag<<3
                siz = len(pkt.data)
                self.__buf[off:off+siz]=pkt.data
                self.__bitm[off:off+siz]=[True]*siz
            def full(self):
                return sum(self.__bitm) == self.__size
            def getvalue(self):
                return bytes(self.__buf)
        self.__phdl = _datafq
        
        self.__recvq = conf.netcache.new_cache("WLTransRecvQue",10)
        self.__s_sig = conf.netcache.new_cache("WLTransRecvSig",10)
        self.__dq = queue.Queue()
        self.__sock = conf.iface.l2socket()(promisc=True,monitor=True)
        self.__tq = ThreadPoolExecutor(4)
        self.__snf = AsyncSniffer(opened_socket=self.__sock,
                                  prn = functools.partial(self.__rcvf,weakref.ref(self)),
                                  store = False)
        self.__snf.start()
        self.__pkt_size = {}
        self.__id = 0
    @staticmethod
    def __rcvf(slf,pkt):
        if not RadioTap in pkt:
            return
        pld = pkt[RadioTap].payload
        if pld is None:
            return
        if len(pld)<85:
            return
        g=slf()
        def __cbk():
            try:
                g.__onrecv(pkt)
            except Exception as e:
                print("Packet corrupted!")
                traceback.print_exc()
        if g is not None:
            g.__tq.submit(__cbk)
    def __send(self,tgt,d,data,size,off,retrans):
        g = threading.Event()
        #print('wait ack',tgt,d,off)
        self.__s_sig[tgt,d,off]=g
        pkt = Wireless_packet(data=data,size=size,frag=off>>3,id=d,flags=('data' if not retrans else 'data+retransmission'))
        wl_sendp(pack_wl_data(tgt,raw(pkt)),socket=self.__sock)
        return g,data,off
    def __sendack(self,tgt,pkt):
        pkt2 = Wireless_packet(data=b'',frag=pkt.frag,id=pkt.id,flags='acknowledge')
        wl_sendp(pack_wl_data(tgt,raw(pkt2)),socket=self.__sock)
    def sendto(self,tgt,data,timeout=2,retransmit_cnt=2):
        if not tgt in self.__pkt_size:
            self.__pkt_size[tgt]=PacketSizeMgr()
        _d=self.__id
        self.__id += 1
        _d &= 0xffffffff
        flg=False
        for i in range(retransmit_cnt):
            b=io.BytesIO(data)
            p=[]
            szzz=self.__pkt_size[tgt].getsize()
            while (t:=b.read(szzz)):
                p.append(self.__send(tgt,_d,t,len(data),b.tell()-len(t),flg))
            if tgt == '::ffff:255.255.255.255':
                #don't check broadcasts
                return True
            t=time.time()+timeout
            wpkts = False
            for g,d,o in p:
                w=t-time.time()
                if w<0 or not g.wait(w):
                    try:
                        del self.__s_sig[tgt,d,o]
                    except KeyError:
                        pass
                    wpkts=True
            if wpkts:
                self.__pkt_size[tgt].onretransmit()
                flg=True
            else:
                return True
        return False
    def __onrecv(self,pkt):
        try:
            dat = unpack_wl_data(pkt)
        except Exception as e:
            #print("Error while decoding",e)
            return
        if dat is None:
            return #abandoned
        saddr,data = dat
        if hasattr(pkt[RadioTap],'dBm_AntSignal') and saddr in self.__pkt_size:
            self.__pkt_size[saddr].onreceive(pkt[RadioTap].dBm_AntSignal)
        wp = Wireless_packet(data)
        #wp.show()
        if wp.flags & 1:
            try:
                hdl = self.__recvq[saddr,wp.id]
            except KeyError:
                hdl = self.__phdl(saddr, wp.size)
            hdl.onrecv(wp)
            #print("send ack",saddr,wp.id,wp.frag)
            self.__sendack(saddr,wp)
            if hdl.full():
                self.__dq.put((saddr,hdl.getvalue()))
                try:
                    del self.__recvq[saddr,wp.id]
                except KeyError:
                    pass
            else:
                self.__recvq[saddr,wp.id]=hdl
        elif wp.flags & 2:
            #print("received ack",saddr,wp.id,wp.frag)
            try:
                self.__s_sig[saddr,wp.id,wp.frag].set()
            except KeyError:
                pass
    def recvfrom(self,timeout=None):
        return self.__dq.get(timeout=timeout)
    def __del__(self):
        try:
            self.__snf.stop()
        except RuntimeError:
            pass
        self.__tq.shutdown()
        self.__wlocker.unlock()
class weak_lru_cache():
    __slots__=('__cache','__dict__')
    def __init__(self):
        self.__cache = functools.lru_cache()
    def __call__(self,func):
        class weak_lru_cache_internal():
            __slots__=('__fn','__ch','__dict__')
            if hasattr(func,'__qualname__'):
                __qualname__ = func.__qualname__
            def __init__(self,ch,fn):
                self.__fn=fn
                self.__ch=ch(self.__callinternal)
            @property
            def __copy__(self):
                return self.__ch.__copy__
            @property
            def __deepcopy__(self):
                return self.__ch.__deepcopy__
            @property
            def __name__(self):
                return self.__fn.__name__
            @property
            def cache_clear(self):
                return self.__ch.cache_clear
            @property
            def cache_info(self):
                return self.__ch.cache_info
            def __callinternal(self,*a,**k):
                r = self.__fn(*a,**k)
                self.__ref = r
                result=lambda:None
                result.ref = weakref.ref(r)
                return result
            def __call__(self,*a,**k):
                r = self.__ch(*a,**k)
                rf = r.ref()
                self.__ref = None
                if rf is None:
                    rf=self.__fn(*a,**k)
                    r.ref = weakref.ref(rf)
                return rf
        return weak_lru_cache_internal(self.__cache,func)
@weak_lru_cache()
class WirelessSocketMgr():
    __slots__=('__ch',
               '__p',
               '__dispatchers',
               '__ddispatch',
               '__dict__',
               '__weakref__')
    def __init__(self,chann):
        self.__ch = chann
        self.__p = WirelessTransportBase(chann)
        self.__dispatchers = {}
        self.__ddispatch = []
    def dispatch(self, timeout):
        try:
            ip,data=self.__p.recvfrom(timeout)
        except queue.Empty:
            return None
        g=self.__dispatchers.get(ip,None)
        if g is not None:
            for i in g:
                i(data)
        for i in  self.__ddispatch:
            i(ip,data)
    def _addsocket(self,ip,cbk):
        d = self.__dispatchers.get(ip,None)
        if d is None:
            d=[]
            self.__dispatchers[ip]=d
        d.append(cbk)
    def _rmvsocket(self,ip,cbk):
        d = self.__dispatchers.get(ip,None)
        if d is None:
            if cbk in d:
                d.remove(cbk)
    def _addbrdsock(self,cbk):
        self.__ddispatch.append(cbk)
    def _rembrdsock(self,cbk):
        if cbk in self.__ddispatch:
            self.__ddispatch.remove(cbk)
    def send(self, ip, data):
        self.__p.sendto(ip,data)
class WlSocket():
    __slots__=('__mgr','__addr',
               '__cb','__msgs',
               '__closed','__dict__',
               '__weakref__')
    def __init__(self,addr,chann=6):
        self.__mgr = WirelessSocketMgr(chann)
        self.__addr = addr
        self.__cb = functools.partial(self.__disp,weakref.ref(self))
        self.__mgr._addsocket(addr,self.__cb)
        self.__msgs = queue.Queue()
        self.__closed = False
    @staticmethod
    def __disp(f,p):
        g=f()
        if g is not None:
            g.__onrcv(p)
    def __onrcv(self,p):
        self.__msgs.put(p)
    def recv(self,timeout=None):
        timeout = -1 if timeout is None else int(timeout*10)
        self.__mgr.dispatch(0)
        if not self.__msgs.empty():
            return self.__msgs.get()
        while timeout:
            self.__mgr.dispatch(0.1)
            if not self.__msgs.empty():
                return self.__msgs.get()
            timeout-=1
        return None
    def send(self,data):
        if isinstance(data,Packet):
            data=bytes(data)
        sef.__mgr.send(self.__addr,data)
    def close(self):
        if self.__closed:
            return
        self.__closed=True
        self.__mgr._rmvsocket(self.__cb)
        self.__mgr=None
    def __del__(self,*a,**k):
        self.close()
class WlBroadcastSocket():
    __slots__=('__mgr','__cb','__msgs','__closed','__dict__','__weakref__')
    def __init__(self,chann=6):
        self.__mgr = WirelessSocketMgr(chann)
        self.__cb = functools.partial(self.__disp,weakref.ref(self))
        self.__mgr._addbrdsock(self.__cb)
        self.__msgs = queue.Queue()
        self.__closed=False
    @staticmethod
    def __disp(f,w,p):
        g=f()
        if g is not None:
            g.__onrcv(w,p)
    def __onrcv(self,w,p):
        self.__msgs.put((w,p))
    def recvfrom(self,timeout=None):
        if not self.__msgs.empty():
            return self.__msgs.get()
        timeout = -1 if timeout is None else int(timeout*10)
        self.__mgr.dispatch(0)
        if not self.__msgs.empty():
            return self.__msgs.get()
        while timeout:
            self.__mgr.dispatch(0.1)
            if not self.__msgs.empty():
                return self.__msgs.get()
            timeout-=1
        return None
    def send(self,data):
        self.__mgr.send('::ffff:255.255.255.255',data)
    def close(self):
        #print("socket closed!")
        if self.__closed:
            return
        self.__closed=True
        self.__mgr._rembrdsock(self.__cb)
        self.__mgr=None
    def __del__(self,*a,**k):
        self.close()
def test():
    a=WlBroadcastSocket(11)
    for i in range(1000):
        a.send(b'Hello, World!'*100)
        r = a.recvfrom(0.01)
        if r is not None:
            print(r)
    input()
