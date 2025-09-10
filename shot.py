import os,pyperclip,psutil,_io,base64,tkinter,ctypes
from PIL import Image,ImageGrab
import win32gui
import cv2,numpy
def takeShot(t):
    wid=win32gui.GetParent(t.winfo_id())
    t.withdraw()
    #ctypes.windll.user32.ShowWindow(wid,0)
    #t.update()
    d=pyperclip.paste()
    pyperclip.copy('')
    os.startfile("SnippingTool.exe")
    while True:
        img = ImageGrab.grabclipboard()
        if img:
            for p in psutil.pids():
                try:
                    proc = psutil.Process(p)
                    if "SnippingTool.exe" in proc.exe():
                        proc.kill()
                except:
                    pass
            break
        else:
            t.update()
    pyperclip.copy(d)
    #ctypes.windll.user32.ShowWindow(wid,1)
    #t.update()
    t.deiconify()
    return img
def saveShot2Bytes(img):
    buf=_io.BytesIO()
    img.save(buf,'jpeg')
    return buf.getvalue()
def previewShotBytes(buf,title='Image'):
    with _io.BytesIO(buf) as f:
        img = Image.open(f)
        img.load()
    nb=numpy.array(img)[:,:,::-1]
    cv2.imshow(title,nb)
    cv2.waitKey(0)
def test():
    a=tkinter.Tk()
    img = takeShot(a)
    buf = saveShot2Bytes(img)
    previewShotBytes(buf)
