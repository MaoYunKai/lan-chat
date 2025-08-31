import traceback
import tkinter
import tkinter.simpledialog
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import tkinter.filedialog
import zlib,pyperclip
import tmpfileplus,lzma
class MyScrollbar(tkinter.Frame):
    def __init__(self, parent, orient=tkinter.VERTICAL, 
                 trough_color="#E1E1E1", 
                 thumb_color="#858585",
                 thumb_pressed_color="#6BA3EF",
                 width=15, command=None, **kwargs):
        super().__init__(parent,** kwargs)
        
        # 配置参数
        self.orient = orient
        self.trough_color = trough_color
        self.thumb_color = thumb_color
        self.thumb_pressed_color = thumb_pressed_color
        self.width = width
        self.is_pressed = False
        self._command = command  # 滚动回调函数
        self.first = 0.0         # 滚动范围起始（0.0-1.0）
        self.last = 0.2          # 滚动范围结束（0.0-1.0）
        
        # 创建Canvas作为绘制区域
        if orient == tkinter.VERTICAL:
            self.canvas = tkinter.Canvas(self, width=width, highlightthickness=0, bd=0)
            super().configure(width=width)
            self.canvas.place(x=0,y=0,width=width,relheight=1.0)
        else:
            self.canvas = tkinter.Canvas(self, height=width, highlightthickness=0, bd=0)
            super().configure(height=width)
            self.canvas.place(x=0,y=0,height=width,relwidth=1.0)
        
        
        # 绘制滚动槽和初始滑块
        self.draw_trough()
        self.draw_thumb()
        
        # 绑定事件
        self.canvas.bind("<ButtonPress-1>", self.on_press)
        self.canvas.bind("<B1-Motion>", self.on_drag)
        self.canvas.bind("<ButtonRelease-1>", self.on_release)
        self.canvas.bind("<MouseWheel>", self.on_mouse_wheel)  # Windows
        self.canvas.bind("<Button-4>", self.on_mouse_wheel)    # Linux
        self.canvas.bind("<Button-5>", self.on_mouse_wheel)    # Linux
        
        # 绑定尺寸变化事件
        self.bind("<Configure>", self.update_layout)
        self.bind("<Visibility>", self.update_layout)

    def set(self, first, last):
        """标准滚动条set方法，设置滚动范围"""
        # 确保值在0.0-1.0范围内
        self.first = max(0.0, min(1.0, float(first)))
        self.last = max(0.0, min(1.0, float(last)))
        self.draw_thumb()
    
    def configure(self, kwargs={}, **cnf):
        """配置方法，支持设置各种属性"""
        kwargs.update(cnf)
        if "command" in kwargs:
            self._command = kwargs.pop("command")
        if "troughcolor" in kwargs:
            self.trough_color = kwargs.pop("troughcolor")
            self.draw_trough()
        if "thumbcolor" in kwargs:
            self.thumb_color = kwargs.pop("thumbcolor")
            self.draw_thumb()
        if "width" in kwargs:
            self.width = kwargs.pop("width")
            self.update_layout()
        return super().configure(** kwargs)
    
    def __setitem__(self, key, value):
        """支持s["command"] = a方式设置属性"""
        if key == "command":
            self._command = value
        else:
            super().__setitem__(key, value)
    
    def __getitem__(self, key):
        """支持s["command"]方式获取属性"""
        if key == "command":
            return self._command
        return super().__getitem__(key)
    
    def draw_trough(self):
        """绘制滚动槽"""
        self.canvas.delete("trough")
        if self.orient == tkinter.VERTICAL:
            self.canvas.create_rectangle(
                0, 0, self.width, self.canvas.winfo_height(),
                fill=self.trough_color, outline="", tags="trough"
            )
        else:
            self.canvas.create_rectangle(
                0, 0, self.canvas.winfo_width(), self.width,
                fill=self.trough_color, outline="", tags="trough"
            )
        self.draw_thumb()  # 确保滑块在槽上面
    
    def draw_thumb(self):
        """绘制滑块"""
        self.canvas.delete("thumb")
        color = self.thumb_pressed_color if self.is_pressed else self.thumb_color
        
        if self.orient == tkinter.VERTICAL:
            # 垂直滚动条
            c_height = self.canvas.winfo_height() or 1
            # 计算滑块高度（基于first和last的差值）
            thumb_height = max(20, int(c_height * (self.last - self.first)))
            y_pos = int(c_height * self.first)
            
            self.thumb = self.canvas.create_rectangle(
                1, y_pos, self.width - 1, y_pos + thumb_height,
                fill=color, outline="", tags="thumb"
            )
        else:
            # 水平滚动条
            c_width = self.canvas.winfo_width() or 1
            thumb_width = max(20, int(c_width * (self.last - self.first)))
            x_pos = int(c_width * self.first)
            
            self.thumb = self.canvas.create_rectangle(
                x_pos, 1, x_pos + thumb_width, self.width - 1,
                fill=color, outline="", tags="thumb", rounded=1
            )
    
    def on_press(self, event):
        """鼠标按下事件"""
        if self.orient == tkinter.VERTICAL:
            c_height = self.canvas.winfo_height() or 1
            thumb_height = max(20, int(c_height * (self.last - self.first)))
            y_pos = int(c_height * self.first)
            
            # 判断是否点击在滑块上
            if y_pos <= event.y <= y_pos + thumb_height:
                self.is_pressed = True
                self.start_pos = event.y
                self.start_first = self.first
            else:
                # 点击在槽上，跳转位置
                new_first = event.y / c_height
                # 确保滑块不会超出范围
                new_first = min(new_first, 1.0 - (self.last - self.first))
                self.first = max(0.0, new_first)
                self._trigger_command()
        else:
            c_width = self.canvas.winfo_width() or 1
            thumb_width = max(20, int(c_width * (self.last - self.first)))
            x_pos = int(c_width * self.first)
            
            if x_pos <= event.x <= x_pos + thumb_width:
                self.is_pressed = True
                self.start_pos = event.x
                self.start_first = self.first
            else:
                new_first = event.x / c_width
                new_first = min(new_first, 1.0 - (self.last - self.first))
                self.first = max(0.0, new_first)
                self._trigger_command()
        
        self.draw_thumb()
    
    def on_drag(self, event):
        """鼠标拖动事件"""
        if not self.is_pressed:
            return
            
        if self.orient == tkinter.VERTICAL:
            c_height = self.canvas.winfo_height() or 1
            delta = event.y - self.start_pos
            new_first = self.start_first + delta / c_height
            # 限制滑块范围
            new_first = min(new_first, 1.0 - (self.last - self.first))
            self.first = max(0.0, new_first)
            self._trigger_command()
        else:
            c_width = self.canvas.winfo_width() or 1
            delta = event.x - self.start_pos
            new_first = self.start_first + delta / c_width
            new_first = min(new_first, 1.0 - (self.last - self.first))
            self.first = max(0.0, new_first)
            self._trigger_command()
    
    def on_release(self, event):
        """鼠标释放事件"""
        self.is_pressed = False
        self.draw_thumb()
    
    def on_mouse_wheel(self, event):
        """鼠标滚轮事件"""
        # 计算滚动增量
        if self.orient == tkinter.VERTICAL:
            # 垂直滚动
            delta = -0.05 if (event.delta > 0 or event.num == 4) else 0.05
        else:
            # 水平滚动
            delta = -0.05 if (event.delta > 0 or event.num == 4) else 0.05
            
        new_first = self.first + delta
        # 限制范围
        new_first = min(new_first, 1.0 - (self.last - self.first))
        self.first = max(0.0, new_first)
        self._trigger_command()
    
    def _trigger_command(self):
        """触发滚动回调命令"""
        if self._command:
            # 调用标准滚动条格式的回调：command("moveto", first)
            self._command("moveto", self.first)
        self.draw_thumb()
    
    def update_layout(self, event=None):
        """更新布局（尺寸变化时调用）"""
        if self.orient == tkinter.VERTICAL:
            super().configure(width=self.width)
            self.canvas.place(x=0,y=0,width=self.width,relheight=1.0)
        else:
            super().configure(height=self.width)
            self.canvas.place(x=0,y=0,height=self.width,relwidth=1.0)
        self.draw_trough()
class ScrolledText(tkinter.Text):
    def __init__(self, master=None, **kw):
        self.frame = tkinter.Frame(master)
        self.vbar = MyScrollbar(self.frame)
        self.vbar.pack(side='right', fill='y')

        kw.update({'yscrollcommand': self.vbar.set})
        tkinter.Text.__init__(self, self.frame, **kw)
        self.pack(side='left', fill='both', expand=True)
        self.vbar['command'] = self.yview

        # Copy geometry methods of self.frame without overriding Text
        # methods -- hack!
        text_meths = vars(tkinter.Text).keys()
        methods = vars(tkinter.Pack).keys() | vars(tkinter.Grid).keys() | vars(tkinter.Place).keys()
        methods = methods.difference(text_meths)

        for m in methods:
            if m[0] != '_' and m != 'config' and m != 'configure':
                setattr(self, m, getattr(self.frame, m))

    def __str__(self):
        return str(self.frame)
class TkinterMessage2(tkinter.Frame):
    def __init__(self,master,*a,**k):
        tkinter.Frame.__init__(self,master)
        self.innerF = tkinter.Frame(self)
        s = 'left'
        if 'message_side' in k:
            s = k.pop('message_side')
        self.msg = tkinter.Label(self.innerF,*a,**k)
        self.msg.pack(side=s,fill='y')
        self.innerF.place(x=0,y=0,relwidth=1.0)
        self.bind("<Configure>",self.__onconfig)
        self.innerF.bind("<Configure>",self.__ongconfig)
        self.cpy_menu = tkinter.Menu(self,tearoff=0)
        self.cpy_menu.add_command(label="Copy",command = self.__copy)
        self.msg.bind("<3>",lambda e:self.cpy_menu.post(e.x_root,e.y_root))
    def __copy(self):
        pyperclip.copy(self.msg['text'])
    def __onconfig(self,e):
        self.msg['wraplength']=self.winfo_width()-13
    def __ongconfig(self,e):
        self['height']=self.innerF.winfo_height()
class FileView(tkinter.Frame):
    @staticmethod
    def createVirtualFile(filename,data,p=None):
        class _Tmp():
            @property
            def name(self):
                return filename
            @property
            def total_size(self):
                return len(data)
            @property
            def data(self):
                return data
            @property
            def download_size(self):
                return (p() if p is not None else len(data))
        return _Tmp()
    def __init__(self,master,file=None,*a,**k):
        tkinter.Frame.__init__(self,master,*a,**k)
        if file is None:
            raise TypeError("file object required")
        nv = tkinter.StringVar()
        tkinter.Entry(self,textvariable=nv,state='readonly',bd=0).grid(row=0,column=0,columnspan=2,sticky='ew')
        nv.set(file.name)
        s = file.total_size
        if s < 1024:
            ss = f'{s}B'
        elif s < 1048576:
            ss = f'{s/1024:.2f}KB'
        elif s < 1073741824:
            ss = f'{s/1048576:.2f}MB'
        else:
            ss = f'{s/1073741824:.2f}GB'
        tkinter.Label(self,text=ss).grid(row=1,column=0)
        self.__f = file
        self.__saved = None
        self.__downsta = tkinter.Label(self)
        self.__dpv = tkinter.DoubleVar(value=0)
        self.__downpro = ttk.Progressbar(self,orient='horizontal',variable=self.__dpv)
        self.__downsta.grid(row=2,column=0,columnspan=2,sticky='ew')
        self.__downpro.grid(row=3,column=0,columnspan=2,sticky='ew')
        self.__upd()
    def __upd(self):
        d = self.__f.download_size
        t = self.__f.total_size
        if d>=t:
            self.__downsta.grid_forget()
            self.__downpro.grid_forget()
            tkinter.Button(self,text='预览',command=self.__preview).grid(row=2,column=0,sticky='ew')
            tkinter.Button(self,text='保存',command=self.__save).grid(row=2,column=1,sticky='ew')
        else:
            self.__downsta['text']=f'下载中... {d*100/t:.2f}'
            self.__dpv.set(d*100/t)
            self.after(300,self.__upd)
    def __save(self):
        fn = tkinter.filedialog.asksaveasfilename(initialfile=self.__f.name)
        self.__saved = fn
        with open(fn,'wb') as f:
            f.write(self.__f.data)
        os.startfile(os.path.dirname(fn))
    def __preview__internal(self):
        tmpfileplus.preview(os.path.splitext(self.__f.name)[1],self.__f.data)
    def __preview(self):
        if self.__saved is not None:
            os.startfile(self.__saved)
        else:
            threading.Thread(target=__preview__internal).start()
class ScrollbarManager():
    def __init__(self,sb,
                 contentSizeGetter,
                 parentSizeGetter,
                 contentPositionGetter,
                 contentPositionSetter,
                 ScrollBarHide,
                 ScrollBarShow):
        self.sb=sb
        self.csg = contentSizeGetter
        self.psg = parentSizeGetter
        self.cpg = contentPositionGetter
        self.cps = contentPositionSetter
        self.sbh = ScrollBarHide
        self.sbs = ScrollBarShow
        self.sbis = True
    def scrolltoButtom(self):
        mm = self.csg()-self.psg()
        if mm<=0:
            if self.sbis:
                self.sbh()
                self.sbis = False
            self.cps(0)
        else:
            dd = self.psg() / self.csg()
            if not self.sbis:
                self.sbs()
                self.sbis = True
            pl = mm
            self.sb.set(pl/mm*(1-dd),pl/mm*(1-dd)+dd)
            self.cps(-pl)
    def onscroll(self,typ,*a):
        mm = self.csg()-self.psg()
        if mm<=0:
            if self.sbis:
                self.sbh()
                self.sbis = False
            self.cps(0)
        else:
            dd = self.psg() / self.csg()
            if not self.sbis:
                self.sbs()
                self.sbis = True
            if typ=='scroll':
                count,how = a
                count = int(count)
                if how=='pages':
                    pl = -self.cpg()+self.psg()*count
                else:
                    pl = -self.cpg()+20*count
            else:
                pos = float(a[0]) / (1-dd)
                pl = mm * pos
            if pl > mm:
                pl=mm
            if pl<0:
                pl=0
            self.sb.set(pl/mm*(1-dd),pl/mm*(1-dd)+dd)
            self.cps(-pl)
    def updatescroll(self):
        mm = self.csg()-self.psg()
        if mm<=0:
            if self.sbis:
                self.sbh()
                self.sbis = False
            self.cps(0)
        else:
            dd = self.psg() / self.csg()
            if not self.sbis:
                self.sbs()
                self.sbis = True
            pl = -self.cpg()
            if pl > mm:
                pl=mm
            if pl<0:
                pl=0
            self.sb.set(pl/mm*(1-dd),pl/mm*(1-dd)+dd)
            self.cps(-pl)
class ScrollableFrame(tkinter.Frame):
    def __init__(self,*a,**k):
        tkinter.Frame.__init__(self,*a,**k)
        self.cont = tkinter.Frame(self)
        self.cont.place(x=0,y=0,relwidth=1.0)
        self.sb = tkinter.Frame(self,bg='#858585')
        self.sb_rect = [0,0,0,0]
        self.scr_pos = 0
        self.bind("<Configure>",lambda e:self.update_scroll())
        self.cont.bind("<Configure>",lambda e:self.update_scroll())
        self.sb_pressed=False
        self.sb.bind("<ButtonPress-1>", self.on_down)
        self.sb.bind("<B1-Motion>", self.on_drag)
        self.sb.bind("<ButtonRelease-1>", self.on_up)
    @property
    def content_height(self):
        return self.cont.winfo_height()
    @property
    def height(self):
        return self.winfo_height()
    @property
    def scroll_pos(self):
        return -self.cont.winfo_y()
    @scroll_pos.setter
    def scroll_pos(self,h):
        self.cont.place(x=0,y=-h,relwidth=1.0)
    @property
    def scroll_max(self):
        return max(self.content_height-self.height,0)
    @property
    def scrollbar_height(self):
        sbh = self.height**2//self.content_height
        if sbh < 20:
            sbh=20
        return sbh
    @property
    def scrollbar_max(self):
        return self.height-self.scrollbar_height
    def update_scroll(self):
        if self.content_height <= self.height:
            self.scroll_pos = 0
            self.sb.place_forget()
            self.sb_rect = [0,0,0,0]
        else:
            #self.scroll_pos = max(0,min(self.scroll_pos,self.scroll_max))
            sbp = self.scrollbar_max*self.scroll_pos//self.scroll_max
            if self.sb_pressed:
                wd=15
                self.sb['bg']='#6BA3EF'
            else:
                wd=5
                self.sb['bg']='#858585'
            self.sb_rect = [self.winfo_width()-wd,sbp,self.winfo_width(),sbp+self.scrollbar_height]
            self.sb.place(x=self.sb_rect[0],y=sbp,width=wd,height=self.scrollbar_height)
    def on_drag(self,event):
        if self.sb_pressed:
            sbp_new = event.y_root + self.sb_dy
            sbp_new = max(0,min(sbp_new,self.scrollbar_max))
            self.scroll_pos = sbp_new * self.scroll_max // self.scrollbar_max
            self.update_scroll()
    def on_down(self,event):
        self.sb_pressed=True
        self.sb_dy = self.sb_rect[1]-event.y_root
        self.update_scroll()
    def on_up(self,event):
        self.sb_pressed=False
        self.update_scroll()
    def container(self):
        return self.cont
    def scrollToBottom(self):
        self.scroll_pos = self.scroll_max
        self.update_scroll()
    def update_layout(self):
        self.update_scroll()
