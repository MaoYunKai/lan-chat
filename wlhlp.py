import ctypes,sys,os,struct,queue,tkinter,pyperclip
import win32api, win32con
import _io,struct
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
import functools
from wlhelpex import open_nm3_device,nm3_set_channel,nm3_set_phy_id,find_nm3_handle
import bchlib
from creedsolo import RSCodec, ReedSolomonError
from hichann import sdh_hash
from jit import *
class GUID(ctypes.Structure):
    _fields_=[
        ('Data1', ctypes.c_ulong),
        ('Data2', ctypes.c_ushort),
        ('Data3', ctypes.c_ushort),
        ('Data4', ctypes.c_ubyte*8)
    ]
HANDLE = ctypes.c_void_p
PHANDLE = ctypes.POINTER(HANDLE)
ULONG = ctypes.c_ulong
DWORD = ctypes.c_uint32
WLAN_API_VERSION = 2
ERROR_SUCCESS = 0

# 枚举和结构定义
class DOT11_OPERATION_MODE(ctypes.c_uint):
    DOT11_OPERATION_MODE_UNKNOWN = 0x00000000
    DOT11_OPERATION_MODE_STATION = 0x00000001
    DOT11_OPERATION_MODE_AP = 0x00000002
    DOT11_OPERATION_MODE_EXTENSIBLE_STATION = 0x00000004
    DOT11_OPERATION_MODE_EXTENSIBLE_AP = 0x00000008
    DOT11_OPERATION_MODE_WFD_DEVICE = 0x00000010
    DOT11_OPERATION_MODE_WFD_GROUP_OWNER = 0x00000020
    DOT11_OPERATION_MODE_WFD_CLIENT = 0x00000040
    DOT11_OPERATION_MODE_MANUFACTURING = 0x40000000
    DOT11_OPERATION_MODE_NETWORK_MONITOR = 0x80000000

class WLAN_INTF_OPCODE(ctypes.c_uint):
    wlan_intf_opcode_current_operation_mode = 12

class DOT11_CURRENT_OPERATION_MODE(ctypes.Structure):
    _fields_ = [
        ("uReserved", ULONG),
        ("uCurrentOpMode", DOT11_OPERATION_MODE)
    ]

class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", ctypes.c_wchar * 256),
        ("isState", DWORD)
    ]

class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", DWORD),
        ("dwIndex", DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)  # 可变长度数组占位
    ]

# 加载WLAN API
wlanapi = ctypes.WinDLL('wlanapi.dll')

# 定义函数原型
wlanapi.WlanOpenHandle.argtypes = [DWORD, ctypes.c_void_p, ctypes.POINTER(DWORD), ctypes.POINTER(HANDLE)]
wlanapi.WlanOpenHandle.restype = DWORD

wlanapi.WlanCloseHandle.argtypes = [HANDLE, ctypes.c_void_p]
wlanapi.WlanCloseHandle.restype = DWORD

wlanapi.WlanEnumInterfaces.argtypes = [HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(WLAN_INTERFACE_INFO_LIST))]
wlanapi.WlanEnumInterfaces.restype = DWORD

wlanapi.WlanSetInterface.argtypes = [
    HANDLE, ctypes.POINTER(GUID), WLAN_INTF_OPCODE, DWORD,
    ctypes.c_void_p, ctypes.c_void_p
]
wlanapi.WlanSetInterface.restype = DWORD

wlanapi.WlanQueryInterface.argtypes = [
    HANDLE, ctypes.POINTER(GUID), WLAN_INTF_OPCODE, ctypes.c_void_p,
    ctypes.POINTER(DWORD), ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p
]
wlanapi.WlanQueryInterface.restype = DWORD

wlanapi.WlanFreeMemory.argtypes = [ctypes.c_void_p]
wlanapi.WlanFreeMemory.restype = None
wlanapi_modes = {
    "monitor": DOT11_OPERATION_MODE.DOT11_OPERATION_MODE_NETWORK_MONITOR,
    "managed": DOT11_OPERATION_MODE.DOT11_OPERATION_MODE_EXTENSIBLE_STATION,
    "master": DOT11_OPERATION_MODE.DOT11_OPERATION_MODE_EXTENSIBLE_AP,
    "wfd_device": DOT11_OPERATION_MODE.DOT11_OPERATION_MODE_WFD_DEVICE,
    "wfd_owner": DOT11_OPERATION_MODE.DOT11_OPERATION_MODE_WFD_GROUP_OWNER,
    "wfd_client": DOT11_OPERATION_MODE.DOT11_OPERATION_MODE_WFD_CLIENT
}
reverse_wlanapi_modes = {v:k for k,v in wlanapi_modes.items()}
def get_wireless_monitors():
    """设置无线接口的监控模式状态"""
    client_handle = HANDLE()
    negotiated_version = DWORD()
    
    # 打开WLAN句柄
    result = wlanapi.WlanOpenHandle(
        WLAN_API_VERSION, 
        None, 
        ctypes.byref(negotiated_version), 
        ctypes.byref(client_handle)
    )
    
    if result != ERROR_SUCCESS:
        raise ctypes.WinError(result)
    
    try:
        # 枚举接口
        interface_list_ptr = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        result = wlanapi.WlanEnumInterfaces(
            client_handle, 
            None, 
            ctypes.byref(interface_list_ptr)
        )
        
        if result != ERROR_SUCCESS:
            raise ctypes.WinError(result)
        
        try:
            interface_list = interface_list_ptr.contents
            target_guid = None
            
            # 查找目标接口
            for i in range(interface_list.dwNumberOfItems):
                # 计算接口信息指针
                interface_info_ptr = ctypes.addressof(interface_list.InterfaceInfo) + i * ctypes.sizeof(WLAN_INTERFACE_INFO)
                interface_info = WLAN_INTERFACE_INFO.from_address(interface_info_ptr)
                # print(interface_info.strInterfaceDescription)
                yield {'name':interface_info.strInterfaceDescription,'guid':interface_info.InterfaceGuid}
        finally:
           # 释放接口列表内存
            wlanapi.WlanFreeMemory(interface_list_ptr)
    finally:
        # 关闭WLAN句柄
        wlanapi.WlanCloseHandle(client_handle, None) 
def set_wifi_monitor_mode(interface_name, enable='monitor', verbose=True):
    """设置无线接口的监控模式状态"""
    client_handle = HANDLE()
    negotiated_version = DWORD()
    
    # 打开WLAN句柄
    result = wlanapi.WlanOpenHandle(
        WLAN_API_VERSION, 
        None, 
        ctypes.byref(negotiated_version), 
        ctypes.byref(client_handle)
    )
    
    if result != ERROR_SUCCESS:
        raise ctypes.WinError(result)
    
    try:
        # 枚举接口
        interface_list_ptr = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        result = wlanapi.WlanEnumInterfaces(
            client_handle, 
            None, 
            ctypes.byref(interface_list_ptr)
        )
        
        if result != ERROR_SUCCESS:
            raise ctypes.WinError(result)
        
        try:
            interface_list = interface_list_ptr.contents
            target_guid = None
            
            # 查找目标接口
            for i in range(interface_list.dwNumberOfItems):
                # 计算接口信息指针
                interface_info_ptr = ctypes.addressof(interface_list.InterfaceInfo) + i * ctypes.sizeof(WLAN_INTERFACE_INFO)
                interface_info = WLAN_INTERFACE_INFO.from_address(interface_info_ptr)
                # print(interface_info.strInterfaceDescription)
                if interface_info.strInterfaceDescription == interface_name:
                    target_guid = interface_info.InterfaceGuid
                    break
            
            if not target_guid:
                raise ValueError(f"Interface '{interface_name}' not found")
            
            op_mode = ULONG(wlanapi_modes[enable])
            
            result = wlanapi.WlanSetInterface(
                client_handle,
                ctypes.byref(target_guid),
                WLAN_INTF_OPCODE.wlan_intf_opcode_current_operation_mode,
                ctypes.sizeof(op_mode),
                ctypes.byref(op_mode),
                None
            )
            
            if result != ERROR_SUCCESS:
                raise ctypes.WinError(result)
            if verbose:
                print(f"Successfully enabled {enable} mode for {interface_name}")
        finally:
            # 释放接口列表内存
            wlanapi.WlanFreeMemory(interface_list_ptr)
    finally:
        # 关闭WLAN句柄
        wlanapi.WlanCloseHandle(client_handle, None)
def get_wifi_mode(interface_name):
    client_handle = HANDLE()
    negotiated_version = DWORD()
    
    # 打开WLAN句柄
    result = wlanapi.WlanOpenHandle(
        WLAN_API_VERSION, 
        None, 
        ctypes.byref(negotiated_version), 
        ctypes.byref(client_handle)
    )
    
    if result != ERROR_SUCCESS:
        raise ctypes.WinError(result)
    
    try:
        # 枚举接口
        interface_list_ptr = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        result = wlanapi.WlanEnumInterfaces(
            client_handle, 
            None, 
            ctypes.byref(interface_list_ptr)
        )
        
        if result != ERROR_SUCCESS:
            raise ctypes.WinError(result)
        
        try:
            interface_list = interface_list_ptr.contents
            target_guid = None
            
            # 查找目标接口
            for i in range(interface_list.dwNumberOfItems):
                # 计算接口信息指针
                interface_info_ptr = ctypes.addressof(interface_list.InterfaceInfo) + i * ctypes.sizeof(WLAN_INTERFACE_INFO)
                interface_info = WLAN_INTERFACE_INFO.from_address(interface_info_ptr)
                # print(interface_info.strInterfaceDescription)
                if interface_info.strInterfaceDescription == interface_name:
                    target_guid = interface_info.InterfaceGuid
                    break
            
            if not target_guid:
                raise ValueError(f"Interface '{interface_name}' not found")
            
            op_mode = ctypes.POINTER(ULONG)()
            size = DWORD()
            
            result = wlanapi.WlanQueryInterface(
                client_handle,
                ctypes.byref(target_guid),
                WLAN_INTF_OPCODE.wlan_intf_opcode_current_operation_mode,
                None,
                ctypes.byref(size),
                ctypes.cast(ctypes.byref(op_mode),ctypes.POINTER(ctypes.c_void_p)),
                None
            )
            
            if result != ERROR_SUCCESS:
                raise ctypes.WinError(result)
            result = reverse_wlanapi_modes.get(op_mode[0],op_mode[0])
            wlanapi.WlanFreeMemory(op_mode)
            return result
        finally:
            # 释放接口列表内存
            wlanapi.WlanFreeMemory(interface_list_ptr)
    finally:
        # 关闭WLAN句柄
        wlanapi.WlanCloseHandle(client_handle, None)
@functools.lru_cache()
def override_iface_modes():
    try:
        from scapy.arch.libpcap import pcap_invalidate
    except:
        pcap_invalidate=lambda:None
    def mode(self):
        return get_wifi_mode(self.description)
    def setmode(self,mode):
        set_wifi_monitor_mode(self.description,mode,False)
        pcap_invalidate()
        self.cache_mode = None
        return True
    t=type(conf.iface)
    t.mode=mode
    t.setmode=setmode
nmapi = None
for i in "ABCDEF":
    NMAPI_DLL_PATH = i+":/Program Files/Microsoft Network Monitor 3/NMAPI.dll"
    try:
        nmapi = ctypes.windll.LoadLibrary(NMAPI_DLL_PATH)
    except:
        pass
    else:
        break
if nmapi is None:
    class _tmp():
        def __getattr__(self,attr):
            def __stub(*__,**___):
                import tkinter
                import tkinter.messagebox
                a=tkinter.Tk()
                a.withdraw()
                tkinter.messagebox.showerror("Error","Microsoft Network Monitor 3 is not installed")
                exit(1)
            return __stub
    nmapi = _tmp()
    del _tmp
NmOpenCaptureEngine = nmapi.NmOpenCaptureEngine
NmOpenCaptureEngine.argtypes = [PHANDLE]
NmOpenCaptureEngine.restype = ULONG
NM_FRAME_CALLBACK = ctypes.WINFUNCTYPE(None,HANDLE,ULONG,ctypes.c_void_p,HANDLE)
class NM_NIC_ADAPTER_INFO(ctypes.Structure):
    _fields_=[
        ("Size",ctypes.c_ushort),
        ("PermanentAddr",ctypes.c_ubyte*6),
        ("CurrentAddr",ctypes.c_ubyte*6),
        ("MediumType",ctypes.c_int),
        ("PhysicalMediumType",ctypes.c_int),
        ("ConnectionName",ctypes.c_wchar*260),
        ("FriendlyName",ctypes.c_wchar*260),
        ("Guid",ctypes.c_wchar*260),
        ("OpState",ctypes.c_int),
        ("Enabled",ctypes.c_int),
        ("PModeEnabled",ctypes.c_int),
        ("CallBackFunction",NM_FRAME_CALLBACK)
    ]
NmGetAdapter = nmapi.NmGetAdapter
NmGetAdapter.argtypes=[HANDLE,ULONG,ctypes.POINTER(NM_NIC_ADAPTER_INFO)]
NmGetAdapter.restype=ULONG
NmGetAdapterCount = nmapi.NmGetAdapterCount
NmGetAdapterCount.argtypes=[HANDLE,ctypes.POINTER(ULONG)]
NmGetAdapterCount.restype=ULONG
NmConfigAdapter = nmapi.NmConfigAdapter
NmConfigAdapter.argtypes=[HANDLE,ULONG,NM_FRAME_CALLBACK,ctypes.c_void_p,ctypes.c_int]
NmConfigAdapter.restype = ULONG
NmGetPartialRawFrame = nmapi.NmGetPartialRawFrame
NmGetPartialRawFrame.argtypes=[HANDLE,ULONG,ULONG,ctypes.POINTER(ctypes.c_byte),ctypes.POINTER(ULONG)]
NmGetPartialRawFrame.restype=ULONG
NmGetRawFrame = nmapi.NmGetRawFrame
NmGetRawFrame.argtypes=[HANDLE,ULONG,ctypes.POINTER(ctypes.c_byte),ctypes.POINTER(ULONG)]
NmGetRawFrame.restype=ULONG
NmGetRawFrameLength = nmapi.NmGetRawFrameLength
NmGetRawFrameLength.argtypes=[HANDLE,ctypes.POINTER(ULONG)]
NmGetRawFrameLength.restype=ULONG
NmStartCapture = nmapi.NmStartCapture
NmStartCapture.argtypes=[HANDLE,ULONG,ctypes.c_int]
NmStartCapture.restype=ULONG
NmStopCapture = nmapi.NmStopCapture
NmStopCapture.argtypes=[HANDLE,ULONG]
NmStopCapture.restype=ULONG
NmResumeCapture = nmapi.NmResumeCapture
NmResumeCapture.argtypes=[HANDLE,ULONG]
NmResumeCapture.restype=ULONG
NmPauseCapture = nmapi.NmPauseCapture
NmPauseCapture.argtypes=[HANDLE,ULONG]
NmPauseCapture.restype=ULONG
NmDiscardRemainFrames = 1
NmReturnRemainFrames = 2
NmLocalOnly = 0
NmPromiscuous = 1
class NmCapture():
    def __checkresult(self,r):
        if r:
            print(r)
            #raise ctypes.WinError(r)
    def __init__(self):
        self.handle = ctypes.c_void_p(0)
        self.__checkresult(NmOpenCaptureEngine(ctypes.byref(self.handle)))
        self.__frameIndication = NM_FRAME_CALLBACK(self.__frameHandler)
        self.__ifaces=[]
        self.__prn = lambda x:x.show()
        self.__hdrkeys = ('Version','Length','OpMode','Flags','PhyType','Channel','lRSSI','Rate','TimeStamp')
        self.__hdrfmt = "<BHIIIIiBQ"
    def setPrn(self,prn):
        self.__prn=prn
    def __frameHandler(self,hdl,adap,ctx,frm):
        fhdl = ctypes.c_void_p(frm)
        size=ULONG()
        self.__checkresult(NmGetRawFrameLength(fhdl,size))
        buf = (ctypes.c_byte*size.value)()
        rl = ULONG()
        pbuf = ctypes.cast(ctypes.pointer(buf),ctypes.POINTER(ctypes.c_byte))
        self.__checkresult(NmGetRawFrame(fhdl,size,pbuf,ctypes.byref(rl)))
        b = bytes(buf)
        hdr = dict(zip(self.__hdrkeys,struct.unpack(self.__hdrfmt,b[:32])))
        try:
            d=Dot11(b[32:])
        except:
            d=Raw(load=b[32:])
        r = RadioTap(version = hdr['Version'],
                     present=4194350,
                     len=28,
                     Flags=hdr['Flags'],
                     dBm_AntSignal=hdr['lRSSI'],
                     Rate=hdr['Rate'],
                     Channel=hdr['Channel'],
                     timestamp=hdr['TimeStamp'],
                     ts_unit=2)/d
        r.time = hdr['TimeStamp'] / 1e9
        r.rawHeaders = hdr
        self.__prn(r)
    def adapterInfo(self):
        size = ULONG()
        self.__checkresult(NmGetAdapterCount(self.handle,ctypes.byref(size)))
        for i in range(size.value):
            info = NM_NIC_ADAPTER_INFO()
            info.Size=ctypes.sizeof(NM_NIC_ADAPTER_INFO)
            self.__checkresult(NmGetAdapter(self.handle,i,ctypes.byref(info)))
            yield {"name":info.FriendlyName,"guid":info.Guid}
    def add_iface(self,iface=None):
        guid = resolve_iface(iface or conf.iface).guid
        size = ULONG()
        self.__checkresult(NmGetAdapterCount(self.handle,ctypes.byref(size)))
        for i in range(size.value):
            info = NM_NIC_ADAPTER_INFO()
            info.Size=ctypes.sizeof(NM_NIC_ADAPTER_INFO)
            self.__checkresult(NmGetAdapter(self.handle,i,ctypes.byref(info)))
            if info.Guid == guid:
                self.__checkresult(NmConfigAdapter(self.handle,i,self.__frameIndication,ctypes.c_void_p(0),NmReturnRemainFrames))
                self.__ifaces.append(i)
                return i
    def set_phyid_and_channel(self,phyid,chann):
        for i in self.__ifaces:
            for h in find_nm3_handle(NmGetAdapter, i):
                nm3_set_phy_id(h,phyid)
                nm3_set_channel(h,chann)
    def start(self):
        for i in self.__ifaces:
            self.__checkresult(NmStartCapture(self.handle,i,NmPromiscuous))
    def stop(self):
        for i in self.__ifaces:
            self.__checkresult(NmStopCapture(self.handle,i))
    def pause(self):
        for i in self.__ifaces:
            self.__checkresult(NmPauseCapture(self.handle,i))
    def resume(self):
        for i in self.__ifaces:
            self.__checkresult(NmPauseCapture(self.handle,i))
def sniff_monitor(iface=None,prn=lambda x:x.show()):
    q=queue.Queue()
    def sync_prn(pkt):
        q.put(pkt)
    a = NmCapture()
    a.setPrn(sync_prn)
    a.add_iface(iface)
    a.start()
    try:
        while True:
            try:
                pkt = q.get(timeout=0.1)
            except queue.Empty:
                continue
            prn(pkt)
    except KeyboardInterrupt:
        a.stop()
    except:
        a.stop()
        raise
def sniff_monitor_store(iface=None,count=None,timeout=None):
    lst=[]
    a = NmCapture()
    a.setPrn(lst.append)
    a.add_iface(iface)
    a.start()
    try:
        t = time.time()
        while True:
            if count:
                if len(lst) >= count:
                    break
            if timeout:
                if time.time() >= t+timeout:
                    break
            time.sleep(0.01)
    except KeyboardInterrupt:
        pass
    a.stop()
    return PacketList(lst, "Sniffed")
def wl_sendp(pkt,socket=None):
    sendp(RadioTap(present='TSFT+Flags',Flags='FCS',mac_timestamp=RandLong())/pkt,socket=socket,monitor=True,verbose=False)
def pkt_get_raw_data(pkt):
    if not Dot11 in pkt:
        return raw(pkt)
    d=raw(pkt[Dot11])
    if d.startswith(b'\x00\x00\x08\x00\x00\x00\x00\x00'):
        return pkt_get_raw_data(RadioTap(d))
    else:
        return d
#Advanced tools
@functools.lru_cache()
def get_oid_data_structure(size):
    class PACKET_OID_DATA(ctypes.Structure):
        _fields_=[('oid',ctypes.c_uint32),
                  ('length',ctypes.c_uint32),
                  ('data',ctypes.c_ubyte*size)]
    return PACKET_OID_DATA
PACKET_DLL = ctypes.cdll.LoadLibrary('packet.dll')
PacketRequest = PACKET_DLL.PacketRequest
PacketRequest.argtypes=[ctypes.c_void_p,ctypes.c_ubyte,ctypes.c_void_p]
PacketRequest.restype=ctypes.c_ubyte
PacketOpenAdapter = PACKET_DLL.PacketOpenAdapter
PacketCloseAdapter = PACKET_DLL.PacketCloseAdapter
PacketOpenAdapter.argtypes=[ctypes.c_char_p]
PacketOpenAdapter.restype=ctypes.c_void_p
PacketCloseAdapter.argtypes=[ctypes.c_void_p]
PacketCloseAdapter.restype=None
PacketGetMonitorMode = PACKET_DLL.PacketGetMonitorMode
PacketGetMonitorMode.argtypes=[ctypes.c_char_p]
PacketGetMonitorMode.restype = ctypes.c_int
def makeOIDRequest(adapter,ioid,bset,pdata,uldatasize):
    adaptername=adapter.network_name.encode()
    PacketGetMonitorMode(adaptername)
    padap=PacketOpenAdapter(adaptername)
    if not padap:
        raise RuntimeError("PacketOpenAdapter ERROR")
    try:
        d1 = struct.pack("<II",ioid,uldatasize)+ctypes.cast(pdata,ctypes.POINTER(ctypes.c_char))[:uldatasize]
        buf=ctypes.create_string_buffer(d1)
        stat=PacketRequest(padap,bset,buf)
        if not stat:
            err=ctypes.GetLastError()&0xffffffff
            err&=~(1<<29)
            raise RuntimeError("NTSTATUS="+hex(err))
        if not bset:
            ctypes.memmove(pdata,buf[8:],uldatasize)
    finally:
        PacketCloseAdapter(padap)
    return stat
OID_DOT11_NDIS_START=0x0d010300
OID_DOT11_CURRENT_CHANNEL=OID_DOT11_NDIS_START + 53
OID_DOT11_CURRENT_FREQUENCY=OID_DOT11_NDIS_START + 66
def getchannel(adapter):
    r=ctypes.c_ulong()
    makeOIDRequest(adapter,OID_DOT11_CURRENT_CHANNEL,False,ctypes.byref(r),4)
    return r.value
def setchannel(adapter,channel):
    a=ctypes.c_ulong(channel)
    makeOIDRequest(adapter,OID_DOT11_CURRENT_CHANNEL,True,ctypes.byref(a),4)
def setchannel2(adapter,phyid,channel):
    a=NmCapture()
    a.add_iface(adapter or conf.iface)
    a.set_phyid_and_channel(phyid,channel)
def test_nmapi_chann_set():
    conf.iface.setmonitor(True)
    a=NmCapture()
    a.add_iface(conf.iface)
    while True:
        for phyid in [1,2,3]:
            for chann in range(1,12):
                a.set_phyid_and_channel(phyid,chann)
                time.sleep(0.03)
@functools.lru_cache()
def override_faces():
    available = set(map(lambda x:x['name'],get_wireless_monitors()))
    available2 = set(map(lambda x:x['guid'],NmCapture().adapterInfo()))
    # 获取所有接口
    all_ifaces = filter(lambda x:x.description in available and x.guid in available2,conf.ifaces.values())

    # 筛选无线接口（根据系统调整匹配规则）
    wireless_pattern = re.compile(r"wlan|wlp|ath|Wi-Fi|Wireless", re.IGNORECASE)
    f = sorted(all_ifaces,key=lambda x:len(wireless_pattern.findall(x.description)),reverse=True)
    if not f:
        raise ValueError("未找到无线接口！")

    # 选择第一个无线接口
    target_iface = f[0]
    conf.iface = target_iface
    override_iface_modes()
#Wireless channels
#recommended 128bytes block
#encoded/raw rate is 1.38
class WLIdentifer(Packet):
    name="Wireless Identifer"
    fields_desc = [
        Emph(SourceIPField('ip_addr')),
        Emph(SourceMACField('mac_addr')),
        StrFixedLenField('machine_name', None, length=16),
        StrFixedLenField('Iface_info', None, length=16)
    ]
@functools.lru_cache()
def get_wlan_identifer():
    idtf = WLIdentifer()
    idtf.mac_addr = conf.iface.mac
    idtf.machine_name = uuid.uuid3(uuid.NAMESPACE_URL,"\\"+socket.gethostname()).bytes
    idtf.Iface_info = uuid.uuid3(uuid.UUID(conf.iface.guid),
                                 json.dumps({'name':conf.iface.name,'description':conf.iface.description})).bytes
    return raw(idtf)
#get the own pseudoIPAddress
#the address is unique
@functools.lru_cache()
def get_wlan_own_addr():
    ident = get_wlan_identifer()
    d = uuid.uuid5(uuid.NAMESPACE_OID,ident.decode("latin-1"))
    return IP6Field.m2i(None,None,d.bytes)
@functools.lru_cache()
class RSCodecCalculator():
    __slots__=('codec','block_size',
               'encoded_block_size','bc_size'
               'bcodec','__dict__','__weakref__')
    def __init__(self,nsym=20,nsize=255):
        self.codec=RSCodec(20)
        self.bcodec=bchlib.BCH(15,m=15)
        self.block_size=nsize-nsym
        self.encoded_block_size=nsize
        self.bc_size=nsym
    def get_check_length(self,length):
        return (length+self.block_size-1)//self.block_size * self.bc_size
    def get_encoded_length(self,length):
        return (length+self.block_size-1)//self.block_size * self.encoded_block_size
    def get_decoded_length(self,length):
        full_blocks,rem = divmod(length,self.encoded_block_size)
        return full_blocks * self.block_size + rem - 20
    def is_valid_real_encoded_length(self,length,min_size=36):
        if length < 49+min_size:
            return False
        if length % self.encoded_block_size <= 20:
            return False
        return True
    def real_get_check_bytes(self,length):
        return length-self.get_decoded_length(length)+29
    def __decode_raw(self,data):
        buf=_io.BytesIO(data[:-20])
        while True:
            yield (a:=buf.read(self.block_size))
            if not a:
                break
            buf.read(self.bc_size)
    def decode_raw(self,data):
        return b''.join(self.__decode_raw(data))
    def encode(self,data):
        bcheck=self.bcodec.encode(data)
        assert len(bcheck)==29
        rdata=self.codec.encode(data+bcheck)
        #print(rdata)
        return bytes(rdata)
    def decode(self,data):
        #print(data)
        try:
            decoded = self.codec.decode(data)[0]
        except ReedSolomonError as err:
            decoded = self.decode_raw(data)
            rs_dec_success=False
            rs_dec_err = err
        else:
            rs_dec_success=True
        bc_data = bytearray(decoded[:-29])
        bc_check = bytearray(decoded[-29:])
        #print(len(bc_data),len(bc_check))
        bc_success = self.bcodec.decode(bc_data,bc_check)>=0
        if bc_success or rs_dec_success:
            self.bcodec.correct(bc_data,bc_check)
            return bytes(bc_data)
        else:
            raise rs_dec_err
    def extract_data_check_bytes(self,data):
        buf=_io.BytesIO(data[:-20])
        data_bytes=[]
        check_bytes=[]
        while True:
            data_bytes.append(a:=buf.read(self.block_size))
            check_bytes.append(buf.read(self.bc_size))
            if not a:
                break
        check_bytes.append(data[-20:]) #for the last incomplete block
        d=b''.join(data_bytes)
        c=b''.join(check_bytes)
        return d[:-29],d[-29:]+c
    def mix_data_check_bytes(self,data,check):
        dbuf=_io.BytesIO(data+check[:29])
        cbuf=_io.BytesIO(check[29:])
        rbuf=[]
        while True:
            rbuf.append(d:=dbuf.read(self.block_size))
            rbuf.append(c:=cbuf.read(self.bc_size))
            if not (d or c):
                break
        return b''.join(rbuf)
def test_fix(length):
    import os,random
    calc=RSCodecCalculator()
    for i in range(100):
        #100 tests
        old_data = os.urandom(length)
        d,c = calc.extract_data_check_bytes(calc.encode(old_data))
        assert d == old_data
        assert calc.is_valid_real_encoded_length(len(d)+len(c))
        d2=calc.decode_raw(calc.mix_data_check_bytes(d,c))
        assert d2[:-29] == d
        assert calc.real_get_check_bytes(len(d)+len(c)) == len(c)
        d=bytearray(d)
        for j in range(10):
            d[random.randint(0,len(d)-1)]=os.urandom(1)[0]
        fixed = calc.decode(calc.mix_data_check_bytes(d,c))
        if fixed != old_data:
            print('fixed=',fixed)
            print('oldd =',old_data)
def compress_2_addresses(addr1,addr2):
    a,b=struct.unpack(">QQ",addr1)
    c,d=struct.unpack(">QQ",addr2)
    p,q=t64(a,d,c,b)
    return struct.pack(">QQ",p,q)
class CorrectCodeField(StrField):
    __slots__ = ["codec"]

    def __init__(self, name, default, fmt="H"):
        Field.__init__(self, name, default, fmt)
        self.codec=RSCodecCalculator()

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, bytes]
        len_pkt = len(s)
        self_size = self.codec.real_get_check_bytes(len_pkt)
        return s[self_size:], self.m2i(pkt, s[:self_size])
class WLData(Packet):
    name='Wireless Data'
    fields_desc = [
        CorrectCodeField('data_check', b''),
        IP6Field('saddr', None),#saddr and daddr is not real IPv6 address
        IP6Field('daddr', None),#they are generated by get_wlan_own_addr()
        StrField('data', None, remain=4),
        XIntField("chksum", None)
    ]
    @property
    def __expected_checksum(self):
        rdr = type(self).saddr.i2m(self,self.saddr)
        rdd = type(self).saddr.i2m(self,self.daddr)
        return sdh_hash(self.data,compress_2_addresses(rdr,rdd))
    def self_build(self):
        if self.chksum is None:
            self.chksum = self.__expected_checksum
        return super().self_build()
    def verify_chksum(self):
        return self.chksum == self.__expected_checksum
    def post_build(self,p,pay,calc=RSCodecCalculator()):
        assert not pay, 'payload not allowed here'
        if self.data_check:
            p=p[len(self.data_check):]
        d,c=calc.extract_data_check_bytes(calc.encode(p))
        assert d == p
        return c+p
    def dissect(self,p,calc=RSCodecCalculator()):
        assert calc.is_valid_real_encoded_length(len(p))
        cb = calc.real_get_check_bytes(len(p))
        chk = p[:cb]
        data = p[cb:]
        fixed = calc.decode(calc.mix_data_check_bytes(data,chk))
        super().dissect(chk + fixed)
def pack_wl_data(tgt="::FFFF:255.255.255.255",data=b'Hello, World!'):
    return WLData(
        saddr=get_wlan_own_addr(),
        daddr=tgt,
        data=data)
def unpack_wl_data(pkt, promisc=False, accept_broadcast=True, accept_self_broadcast=False):
    if not WLData in pkt:
        rd=raw(pkt[RadioTap].payload)
    else:
        rd=raw(pkt[WLData])
    try:
        d_unp = WLData(rd)
    except Exception as e:
        if not isinstance(e,(AssertionError,ReedSolomonError)):
            print("decode fail",e)
        return None
    #d_unp.show()
    #second: extract the information
    flag = promisc or d_unp.daddr == get_wlan_own_addr()
    if accept_broadcast and not flag:
        flag = d_unp.daddr == '::ffff:255.255.255.255'
        if flag and not accept_self_broadcast:
            flag = not d_unp.saddr == get_wlan_own_addr()
    if d_unp.verify_chksum() and flag:
        return d_unp.saddr,d_unp.data
    else:
        #print("drop ",flag)
        return None
def pack_upack_test():
    a=pack_wl_data(data=b'Hello, World!'*100)
    u=bytes(a)
    p,r=unpack_wl_data(RadioTap()/u,False,True,True)
    assert r==b'Hello, World!'*100
