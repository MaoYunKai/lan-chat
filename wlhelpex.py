from ctypes import *
from ctypes.wintypes import *
import sys

# 加载 kernel32.dll
kernel32 = windll.kernel32

# 定义 Windows 常量
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

# 从您的发现中得到的IOCTL代码
IOCTL_NM3_SET_CHANNEL = 0x210098
IOCTL_NM3_SET_PHY_ID = 0x2100A0

# 特定的访问权限值（从您的发现中获得）
NM3_ACCESS_MODE = 0x120089

def open_nm3_device():
    """
    使用正确的设备名称和访问权限打开 NM3 设备
    """
    device_name = r"\\.\nm3"  # 用户空间访问 \DosDevices\nm3 的方式
    
    handle = kernel32.CreateFileA(
        device_name.encode('ascii'),
        NM3_ACCESS_MODE,  # 使用您发现的特定访问权限
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    
    if handle == INVALID_HANDLE_VALUE:
        error = kernel32.GetLastError()
        print(f"Failed to open NM3 device: error {error}")
        return None
    else:
        print("Successfully opened NM3 device")
        return handle

def nm3_set_channel(device_handle, channel):
    """
    使用未文档化的NM3 IOCTL设置信道
    """
    # 准备输入缓冲区 - 根据您的发现，这是一个简单的int
    channel_buf = c_int(channel)
    bytes_returned = DWORD()
    
    # 调用 DeviceIoControl
    success = kernel32.DeviceIoControl(
        device_handle,
        IOCTL_NM3_SET_CHANNEL,
        byref(channel_buf),
        sizeof(channel_buf),
        None,
        0,
        byref(bytes_returned),
        None
    )
    
    if not success:
        error = kernel32.GetLastError()
        print(f"Failed to set channel via NM3 IOCTL: error {error}")
        return False
    else:
        #print(f"Successfully set channel to {channel} via NM3 IOCTL!")
        return True

def nm3_set_phy_id(device_handle, phy_id):
    """
    使用未文档化的NM3 IOCTL设置物理层类型
    phy_id: 例如 1 (802.11b), 2 (802.11a), 3 (802.11g), 4 (802.11n), 等等
    """
    phy_buf = c_int(phy_id)
    bytes_returned = DWORD()
    
    success = kernel32.DeviceIoControl(
        device_handle,
        IOCTL_NM3_SET_PHY_ID,
        byref(phy_buf),
        sizeof(phy_buf),
        None,
        0,
        byref(bytes_returned),
        None
    )
    
    if not success:
        error = kernel32.GetLastError()
        print(f"Failed to set PHY ID via NM3 IOCTL: error {error}")
        return False
    else:
        #print(f"Successfully set PHY ID to {phy_id} via NM3 IOCTL!")
        return True
def find_nm3_handle(NmGetAdapter,adapter):
    GetSingletonInstance = ctypes.cast(NmGetAdapter,ctypes.c_void_p).value + 365240
    GetSingletonInstance = ctypes.cast(ctypes.c_void_p(GetSingletonInstance),ctypes.CFUNCTYPE(ctypes.c_void_p))
    result = GetSingletonInstance()+368
    EnumerateNetworkAdapters = ctypes.cast(NmGetAdapter,ctypes.c_void_p).value + 430756
    GetNetworkAdapter = ctypes.cast(NmGetAdapter,ctypes.c_void_p).value + 431412
    if isinstance(adapter,int):
        GetNetworkAdapter = ctypes.cast(ctypes.c_void_p(GetNetworkAdapter),ctypes.CFUNCTYPE(ctypes.c_void_p,
                                                                                            ctypes.c_void_p,
                                                                                            ctypes.c_int))
        ad=ctypes.c_void_p(GetNetworkAdapter(result,adapter))
    else:
        EnumerateNetworkAdapters = ctypes.cast(ctypes.c_void_p(EnumerateNetworkAdapters), ctypes.CFUNCTYPE(ctypes.c_int,
                                                                                                           ctypes.c_void_p,
                                                                                                           ctypes.c_void_p,
                                                                                                           ctypes.c_char_p,
                                                                                                           ctypes.POINTER(ctypes.c_int),
                                                                                                           ctypes.POINTER(ctypes.c_void_p)))
        pMac = b''.join(map(lambda x:bytes([int(x,16)]),adapter.mac.split(":")))+b'\x00\x00'
        unused=ctypes.c_int()
        ad=ctypes.c_void_p()
        EnumerateNetworkAdapters(result, pMac, adapter.description.encode(), ctypes.byref(unused), ctypes.byref(ad))
        print(unused)
    a=ctypes.cast(ad,ctypes.POINTER(ctypes.c_longlong))[302]
    start = ctypes.cast(ctypes.c_void_p(a+24),ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    length = ctypes.cast(ctypes.c_void_p(a+32),ctypes.POINTER(ctypes.c_int))[0]
    for i in range(length):
        addr = start[i]
        hdl = ctypes.cast(addr,ctypes.POINTER(ctypes.c_void_p))[239]
        yield hdl
def main():
    # 1. 打开NM3设备
    device_handle = open_nm3_device()
    if not device_handle:
        print("Please run this script as Administrator and ensure Npcap/Network Monitor is installed")
        return
    
    try:
        # 2. 设置物理层类型（例如，802.11n）
        if not nm3_set_phy_id(device_handle, 4):
            print("Failed to set PHY ID. The device may not support this operation.")
            return
        
        # 3. 设置信道（例如，信道6）
        if not nm3_set_channel(device_handle, 6):
            print("Failed to set channel. The device may not support this operation.")
            return
        
        print("Channel and PHY type set successfully!")
        print("You can now use Scapy or other tools to capture packets on this channel")
        
        # 4. 示例：使用Scapy开始抓包
        # from scapy.all import *
        # sniff(iface="your_interface_name", prn=lambda x: x.summary(), store=0)
        
    finally:
        # 5. 关闭设备句柄
        kernel32.CloseHandle(device_handle)

if __name__ == "__main__":
    # 检查管理员权限
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        print("This script requires administrator privileges to run.")
        print("Please run it as Administrator.")
        sys.exit(1)
    
    main()
