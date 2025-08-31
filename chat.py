import traceback
from wlchatchan import *
from uiwidgets import *

class MainWindow():
    def __init__(self):
        self.tk = tkinter.Tk()
        self.tk.withdraw()
        self.chat_id = tkinter.simpledialog.askinteger("加入/创建聊天室","聊天室id？(负数表示无线聊天，数值是信道）")
        while self.chat_id is None or self.chat_id<-15 or self.chat_id > 65535:
            if self.chat_id is None:
                self.chat_id = tkinter.simpledialog.askinteger("加入/创建聊天室","聊天室id？(负数表示无线聊天，数值是信道）")
            else:
                self.chat_id = tkinter.simpledialog.askinteger("聊天室id必须在-15到65535之间","聊天室id？(负数表示无线聊天，数值是信道）")
        self.room = create_chatroom(self.chat_id)
        self.upd_title()
        self.tk.protocol("WM_DELETE_WINDOW",self._closew)
        self.tk.deiconify()
        self.tk.geometry('800x600')
        self._tf = ScrollableFrame(self.tk,height=300)
        self.tf = self._tf.container()
        self.tf.columnconfigure(0,minsize=30,weight=1)
        self.tf.columnconfigure(1,weight=2)
        self.tf.columnconfigure(2,minsize=30,weight=1)
        self.message_count=0
        self.bf = tkinter.Frame(self.tk)
        self._tf.pack(side='top',fill='both',expand=True)
        self.bf.pack(side='bottom',fill='both')
        self.tx = ScrolledText(self.bf,height=6)
        self.tx.bind("<Control-Return>",self._send)
        self.sdb= tkinter.Button(self.bf,text='发送',command=self._send)
        tkinter.Label(self.bf,text="Enter换行，Ctrl+Enter发送").grid(row=1,column=0,sticky='nsw')
        self.tx.grid(row=0,column=0,columnspan=2,sticky='nsew')
        self.sdb.grid(row=1,column=1)
        self.bf.rowconfigure(0,weight=1)
        self.bf.columnconfigure(0,weight=1)
        self._r = threading.Thread(target=self._receiv_thread)
        self._r.start()
    def _send(self,*_):
        t = self.tx.get('0.0','end').strip()
        self.tx.delete('0.0','end')
        if t:
            if os.path.exists(t):
                self._send_file(t)
                return 'break'
            if len(t)<32768:
                self.__post_msg(None,t,1)
                self.room.send(t)
            else:
                d=t.encode('utf-8')
                n=str(uuid.uuid4())+'.txt'
                p=self.room.sendfile(n,d)
                self.__post_msg(None,FileView.createVirtualFile(n,d,p),1)
        return 'break'
    def _send_file(self,filename,*_):
        n=os.path.basename(filename)
        with open(filename,'rb') as f:
            d=f.read()
        p=self.room.sendfile(n,d)
        self.__post_msg(None,FileView.createVirtualFile(n,d,p),1)
    def _receiv_thread(self):
        while True:
            ip,data=self.room.recv()
            self.tk.after(0,lambda:self.__post_msg(ip,data,0))
    def upd_title(self):
        self.tk.title(f"加密聊天室#{self.chat_id} [{self.room.user_cnt}人在线]")
        self.tk.after(500,self.upd_title)
    def __post_msg(self,who,what,where):
        if where:
            tkinter.Label(self.tf).grid(row=self.message_count<<1,column=0,sticky='nsew')
            if isinstance(what,(str,bytes)):
                m = TkinterMessage2(self.tf,text=what,bg='#95ec69',anchor='w',justify='left',message_side='right')
                m.grid(row=(self.message_count<<1)|1,column=1,columnspan=2,sticky='nsew')
            else:
                m = FileView(self.tf,file=what)
                m.grid(row=(self.message_count<<1)|1,column=1,columnspan=2,sticky='nse')
            self.message_count+=1
        elif who == 'System':
            m = TkinterMessage2(self.tf,text=what,anchor='w',fg='#747677',justify='left')
            m.grid(row=(self.message_count<<1),column=1,sticky='nsew')
            self.message_count+=1
        else:
            tkinter.Label(self.tf,text=who,fg='#A2A3A5',justify='left',anchor='w').grid(row=self.message_count<<1,column=0,sticky='nsew')
            if isinstance(what,(str,bytes)):
                m = TkinterMessage2(self.tf,text=what,bg='#ffffff',anchor='w',justify='left',message_side='left')
                m.grid(row=(self.message_count<<1)|1,column=0,columnspan=2,sticky='nsew')
            else:
                m = FileView(self.tf,file=what)
                m.grid(row=(self.message_count<<1)|1,column=0,columnspan=2,sticky='nsw')
            self.message_count+=1
        def upd():
            self._tf.update_layout()
            self._tf.scrollToBottom()
        self.tk.after(100,upd)
    def _closew(self):
        self.room.quit()
        self.tk.destroy()
    def run(self):
        self.tk.mainloop()
if __name__ == "__main__":
    MainWindow().run()
