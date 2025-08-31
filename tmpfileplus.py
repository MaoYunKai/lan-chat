import subprocess,os,ctypes,tempfile,time,uuid,psutil,win32gui,ctypes
def create_vdisk_d(vdh_path,size):
    command=f'''create vdisk file={vdh_path} maximum={30+size}
select vdisk file={vdh_path}
attach vdisk
create partition primary
format fs=ntfs
assign letter=Z
exit'''
    p = subprocess.Popen(['diskpart'],shell=True,stdin=-1,stdout=-1,stderr=-1)
    p.stdin.write(command.encode())
    o,e=p.communicate()
    p.wait()
    time.sleep(1)
    return (o,e)
def detach_vdisk_d(vdh_path):
    command=f'''select vdisk file={vdh_path}
detach vdisk
exit'''
    p = subprocess.Popen(['diskpart'],shell=True,stdin=-1,stdout=-1,stderr=-1)
    p.stdin.write(command.encode())
    o,e=p.communicate()
    p.wait()
    time.sleep(1)
    os.remove(vdh_path)
    return (o,e)
def waitForProcessOpen(path):
    while True:
        for i in psutil.pids():
            try:
                p=psutil.Process(i)
            except:
                pass
            else:
                c=p.cmdline()
                if c:
                    if c[-1]==path:
                        return i
        time.sleep(0.1)
def waitForWindowOpen(pid):
    def _windows():
        l=[]
        win32gui.EnumWindows(lambda a,l:l.append(a),l)
        return l
    def w_pid(w):
        p=ctypes.c_int()
        ctypes.windll.user32.GetWindowThreadProcessId(w,ctypes.byref(p))
        return p.value
    while True:
        for i in _windows():
            if w_pid(i) == pid:
                return True
        try:
            psutil.Process(pid)
        except:
            return False
        time.sleep(0.1)
def preview(file_suffix, file_data):
    vdhp=os.path.join(tempfile._get_default_tempdir(),str(uuid.uuid4()))+'.vhd'
    try:
        create_vdisk_d(vdhp, len(file_data)//1048576+1)
        fn="Z:\\"+str(uuid.uuid4())+file_suffix
        with open(fn,'wb') as f:
            f.write(file_data)
        os.startfile(fn)
        waitForWindowOpen(waitForProcessOpen(fn))
        time.sleep(1)
    finally:
        detach_vdisk_d(vdhp)
#preview('.cpp',b'''#include<iostream>
#using namespace std;
#int main(){
#    cout<<"Hello, World!"<<endl;
#}''')
