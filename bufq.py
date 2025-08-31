import threading,queue
from typing import Optional
class ThreadSafeBuffer():
    def __init__(self, capacity: int = 1024 * 1024):  # 默认1MB容量
        self.capacity = capacity
        self.buffer = bytearray(capacity)
        self.read_pos = 0
        self.write_pos = 0
        self.bytes_written = 0  # 总写入字节数
        self.bytes_read = 0     # 总读取字节数
        self.closed = False
        
        # 同步原语
        self.lock = threading.RLock()
        self.not_empty = threading.Condition(self.lock)  # 有数据可读的条件
        self.not_full = threading.Condition(self.lock)   # 有空间可写的条件
        
    def write(self, data: bytes) -> int:
        """将数据写入缓冲区，返回实际写入的字节数"""
        with self.not_full:
            if self.closed:
                raise ValueError("Buffer is closed")
                
            total_written = 0
            data_len = len(data)
            
            while total_written < data_len:
                # 计算可用空间
                available = self._available_space()
                if available == 0:
                    # 等待有空间可写
                    self.not_full.wait()
                    if self.closed:
                        break
                    continue
                
                # 计算本次可写入的字节数
                to_write = min(data_len - total_written, available)
                
                # 计算写入位置（考虑循环缓冲区）
                write_index = self.write_pos % self.capacity
                end_index = write_index + to_write
                
                if end_index <= self.capacity:
                    # 不需要环绕
                    self.buffer[write_index:end_index] = data[total_written:total_written+to_write]
                else:
                    # 需要环绕
                    first_part = self.capacity - write_index
                    self.buffer[write_index:self.capacity] = data[total_written:total_written+first_part]
                    self.buffer[0:end_index-self.capacity] = data[total_written+first_part:total_written+to_write]
                
                # 更新位置和计数
                self.write_pos += to_write
                self.bytes_written += to_write
                total_written += to_write
                
                # 通知可能有数据可读
                self.not_empty.notify_all()
            
            return total_written
    
    def read(self, size: int, timeout: Optional[float] = None) -> bytes:
        """从缓冲区读取指定大小的数据，可能返回少于请求的数据"""
        with self.not_empty:
            if self.closed and self._available_data() == 0:
                return b""  # 缓冲区已关闭且无数据
                
            # 等待数据可用
            end_time = time.time() + timeout if timeout else None
            while self._available_data() == 0 and not self.closed:
                if timeout is not None:
                    remaining = end_time - time.time()
                    if remaining <= 0:
                        return b""
                    self.not_empty.wait(remaining)
                else:
                    self.not_empty.wait()
            
            # 计算实际可读取的字节数
            to_read = min(size, self._available_data())
            if to_read == 0:
                return b""
            
            # 创建结果缓冲区
            result = bytearray(to_read)
            
            # 计算读取位置（考虑循环缓冲区）
            read_index = self.read_pos % self.capacity
            end_index = read_index + to_read
            
            if end_index <= self.capacity:
                # 不需要环绕
                result[:] = self.buffer[read_index:end_index]
            else:
                # 需要环绕
                first_part = self.capacity - read_index
                result[0:first_part] = self.buffer[read_index:self.capacity]
                result[first_part:to_read] = self.buffer[0:end_index-self.capacity]
            
            # 更新位置和计数
            self.read_pos += to_read
            self.bytes_read += to_read
            
            # 通知可能有空间可写
            self.not_full.notify_all()
            
            return bytes(result)
    
    def peek(self, size: int) -> bytes:
        """查看但不消费缓冲区中的数据"""
        with self.lock:
            to_read = min(size, self._available_data())
            if to_read == 0:
                return b""
            
            result = bytearray(to_read)
            read_index = self.read_pos % self.capacity
            end_index = read_index + to_read
            
            if end_index <= self.capacity:
                result[:] = self.buffer[read_index:end_index]
            else:
                first_part = self.capacity - read_index
                result[0:first_part] = self.buffer[read_index:self.capacity]
                result[first_part:to_read] = self.buffer[0:end_index-self.capacity]
            
            return bytes(result)
    
    def close(self):
        """关闭缓冲区，不再接受写入"""
        with self.lock:
            self.closed = True
            # 唤醒所有等待的线程
            self.not_full.notify_all()
            self.not_empty.notify_all()
    
    def _available_data(self) -> int:
        """计算可用数据量"""
        return self.write_pos - self.read_pos
    
    def _available_space(self) -> int:
        """计算可用空间"""
        return self.capacity - self._available_data()
    
    def get_stats(self) -> dict:
        """获取缓冲区统计信息"""
        with self.lock:
            return {
                "capacity": self.capacity,
                "available_data": self._available_data(),
                "available_space": self._available_space(),
                "bytes_written": self.bytes_written,
                "bytes_read": self.bytes_read,
                "closed": self.closed
            }
