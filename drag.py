import ctypes,os,struct,_io
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext as sct
import ctypes.wintypes as wintypes
import win32gui
import win32con
import win32api
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import json
#Usage:
#self.root.bind("<<DropFiles>>", f'if {{"[{self.root.register(self.handle_drop)} %d]" == "break"}} break\n')
#drop_manager.install_hook()
# 定义必要的Windows常量
WH_GETMESSAGE = 3
WM_DROPFILES = 0x0233
PM_REMOVE = 1

# 定义钩子过程类型
HOOKPROC = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_int,
    ctypes.c_long,
    ctypes.c_long
)

# 定义MSG结构
class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", wintypes.WPARAM),
        ("lParam", wintypes.LPARAM),
        ("time", wintypes.DWORD),
        ("pt", wintypes.POINT),
    ]

# 定义Shell32函数
shell32 = ctypes.WinDLL('shell32')
DragQueryFile = shell32.DragQueryFileW
DragQueryFile.argtypes = [wintypes.HANDLE, wintypes.UINT, ctypes.c_wchar_p, wintypes.UINT]
DragQueryFile.restype = wintypes.UINT

class DropManager:
    def __init__(self, root):
        self.root = root
        self.hook = None
        self.hook_thread_id = None
        self.target_hwnd = None
        self.running = True
        
        # 获取主窗口句柄
        self.root.update_idletasks()
        self.target_hwnd = win32gui.GetParent(self.root.winfo_id())
        
        # 设置窗口接受拖放
        self.set_drop_target()
        
        # 启动消息处理线程
        #self.thread = threading.Thread(target=self.message_thread, daemon=True)
        #self.thread.start()
        self.Exec = ThreadPoolExecutor(1)
        
        # 确保在程序退出时清理资源
        self.root.bind("<Destroy>", self.on_destroy)
    
    def set_drop_target(self):
        """设置窗口接受拖放"""
        ex_style = win32gui.GetWindowLong(self.target_hwnd, win32con.GWL_EXSTYLE)
        ex_style |= win32con.WS_EX_ACCEPTFILES
        win32gui.SetWindowLong(self.target_hwnd, win32con.GWL_EXSTYLE, ex_style)
    
    def install_hook(self):
        """安装WH_GETMESSAGE钩子"""
        self.hook_thread_id = win32api.GetCurrentThreadId()
        
        self.hook_proc_ptr = HOOKPROC(self.hook_proc)
        self.hook = ctypes.windll.user32.SetWindowsHookExW(
            WH_GETMESSAGE,
            self.hook_proc_ptr,
            0,
            self.hook_thread_id
        )
        
        if not self.hook:
            raise ctypes.WinError()
    
    def hook_proc(self, nCode, wParam, lParam):
        """钩子过程，处理消息"""
        if nCode >= 0 and wParam == PM_REMOVE:
            # 获取消息
            msg = ctypes.cast(lParam, ctypes.POINTER(MSG)).contents
            #print(msg.messsage)
            # 只处理目标窗口的拖放消息
            if msg.hwnd == self.target_hwnd and msg.message == WM_DROPFILES:
                self.process_drop_files(msg.wParam)
                
                # 标记消息为已处理
                return 1  # 返回非零值表示已处理
        
        # 传递给下一个钩子
        return ctypes.windll.user32.CallNextHookEx(self.hook, nCode, wParam, lParam)
    
    def process_drop_files(self, hdrop):
        """处理拖放的文件"""
        # 获取文件数量
        file_count = DragQueryFile(hdrop, 0xFFFFFFFF, None, 0)
        files = []
        
        # 遍历每个文件
        for i in range(file_count):
            # 获取路径长度
            path_len = DragQueryFile(hdrop, i, None, 0)
            
            # 创建缓冲区并获取路径
            buffer = ctypes.create_unicode_buffer(path_len + 1)
            DragQueryFile(hdrop, i, buffer, path_len + 1)
            files.append(buffer.value)
        
        # 释放拖放资源
        shell32.DragFinish(hdrop)
        #print(files)
        # 在Tkinter主线程中触发事件
        self.Exec.submit(lambda:self.root.after(0, lambda: self.root.event_generate("<<DropFiles>>", data=json.dumps(files))))
    
    def on_destroy(self, event):
        """窗口销毁时清理资源"""
        if event.widget == self.root:
            self.running = False
            self.Exec.shutdown()
