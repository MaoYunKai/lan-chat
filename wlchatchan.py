from wltrans import *
from chatchannels import *
from wlhlp import get_wlan_own_addr as get_self_ip
class WlIcmpSocket():
    def __init__(self,ip,start=True,channel=11):
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
        self.__esps = WlSocket(ip,channel)
        self.__closed = False
        self.__alive = True
        self.__rcvt = threading.Thread(target=self.__receiving_msgs)
        self.__rcvt.start()
        if start:
            #print("sending WAKEUP")
            #self.__sniffer.start()
            self.__connect()
    def __receiving_msgs(self):
        while not self.__closed:
            r=self.__esps.recv(0.1)
            if r is not None:
                self.__recv_pkt(r)
    def start_heartbeat(self):
        msg = IcmpMessage(type='heartbeat')
        while not self.__closed:
            self.__esps.send(msg)
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
            self.__esps.send(IcmpMessage(type='wakeup'))
            try:
                self.__wakeup_signal.get(timeout=0.5)
            except:
                pass
            else:
                for j in range(10):
                    self.__esps.send(IcmpMessage(type='wakeup_established'))
                    try:
                        self.__establ_signal.get(timeout=0.5)
                    except:
                        pass
                    else:
                        self.__esps.send(IcmpMessage(type='established'))
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
                self.__esps.send(p)
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
            self.__rcvt.join()
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
        self.__esps.send(IcmpMessage(type='acknowledge',message=IcmpMessageData(data=b'ack',seq=sq)))
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
class WlChatRoomNetwork():
    def __init__(self, ident, uhdl, rhdl):
        self.__id = ident
        self.__ip = get_self_ip()
        self.__usrhdl = uhdl
        self.__chkrun = rhdl
        self.__bcast_magic=b"CHATROOM_ANNOUNCEMENT"
        self.__sock=WlBroadcastSocket(ident)
        self.__sbc = threading.Thread(target=self.__send_broadcasts)
        self.__sbc.start()
        self.__st = threading.Thread(target=self.__sniff_broadcast)
        self.__st.start()
    @property
    def ip_addr(self):
        return self.__ip
    @property
    def __running(self):
        return self.__chkrun()
    def __send_broadcasts(self):
        while self.__running:
            self.__sock.send(self.__bcast_magic)
            time.sleep(1)
    def __sniff_broadcast(self):
        while self.__running:
            d=self.__sock.recvfrom(0.1)
            if d is None:
                continue
            ip,data=d
            if data == self.__bcast_magic:
                self.__usrhdl(ip)
    def create_sock(self,ipaddr):
        return WlIcmpSocket(channel=self.__id)
    def stop(self):
        self.__st.join()
        self.__sbc.join()
        self.__sock.close()
def create_chatroom(chat_id):
    if chat_id >= 0:
        return ChatRoom(chat_id)
    else:
        return ChatRoom(-chat_id, WlChatRoomNetwork)
