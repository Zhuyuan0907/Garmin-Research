"""Temporary, guarded host-memory override for an attended HFP experiment."""
import os
from pathlib import Path
import subprocess
import sys

IDLE = b'0,0,0,0,0,0,%d\x00'


class LiveCindFormat:
    def __init__(self, pid):
        self.fd = None
        self.watch_write = None
        self.watch = None
        executable = Path(f'/proc/{pid}/exe').resolve()
        if executable.name != 'bluealsa':
            raise RuntimeError('Live override is restricted to the BlueALSA daemon')
        data = executable.read_bytes()
        if data.count(IDLE) != 1:
            raise RuntimeError('Stock CIND format must occur exactly once')
        offset = data.index(IDLE)
        self.address = None
        for line in Path(f'/proc/{pid}/maps').read_text().splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[-1] != str(executable):
                continue
            start, end = [int(x, 16) for x in parts[0].split('-')]
            file_offset = int(parts[2], 16)
            if file_offset <= offset and offset + len(IDLE) <= file_offset + end-start:
                self.address = start + offset-file_offset
                break
        if self.address is None:
            raise RuntimeError('CIND format is not mapped in the running daemon')
        self.fd = os.open(f'/proc/{pid}/mem', os.O_RDWR)
        try:
            if os.pread(self.fd, len(IDLE), self.address) != IDLE:
                raise RuntimeError('Live CIND format differs from stock; refusing to modify it')
            read_fd, self.watch_write = os.pipe()
            watcher = 'import os,sys;fd,r,a=int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]);os.read(r,1);os.pwrite(fd,bytes.fromhex(sys.argv[4]),a)'
            self.watch = subprocess.Popen([sys.executable, '-c', watcher, str(self.fd), str(read_fd), str(self.address), IDLE.hex()],
                                          pass_fds=(self.fd, read_fd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.close(read_fd)
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def set(self, active, setup):
        value = f'1,{int(active)},{setup},0,4,0,%d'.encode()+b'\x00'
        if len(value) != len(IDLE) or setup not in range(4):
            raise ValueError('Invalid CIND state')
        if os.pwrite(self.fd, value, self.address) != len(value) or os.pread(self.fd, len(value), self.address) != value:
            raise RuntimeError('Live CIND format update could not be verified')

    def restore(self):
        if self.fd is None:
            return
        try:
            os.pwrite(self.fd, IDLE, self.address)
        finally:
            if self.watch_write is not None:
                os.close(self.watch_write)
                self.watch_write = None
            if self.watch is not None:
                self.watch.wait(timeout=3)
            os.close(self.fd)
            self.fd = None
