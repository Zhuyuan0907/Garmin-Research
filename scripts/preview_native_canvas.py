#!/usr/bin/env python3
"""Encode captured native RGB565 pixel words as lossless PNG for inspection.

This interprets a raw 480x272 software canvas; it is not a device screenshot.
The enlarged crop repeats each existing pixel with no smoothing or new glyphs.
"""
from pathlib import Path
import struct
import zlib
from analyze_native_sections import ROOT


def chunk(name,data):
    return struct.pack('>I',len(data))+name+data+struct.pack('>I',zlib.crc32(name+data))


def png(path,rows,width,height):
    assert len(rows)==height and all(len(row)==width*3 for row in rows)
    path.write_bytes(b'\x89PNG\r\n\x1a\n'+
        chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))+
        chunk(b'IDAT',zlib.compress(b''.join(b'\0'+row for row in rows)))+chunk(b'IEND',b''))


def main():
    stage=ROOT/'staging/native-player-rendering'
    raw=(stage/'loaded-canvas.bin').read_bytes()
    assert len(raw)==480*272*2
    values=struct.unpack('<130560H',raw)
    pixels=[bytes((((v>>11)&31)*255//31,((v>>5)&63)*255//63,(v&31)*255//31))for v in values]
    rows=[b''.join(pixels[y*480:(y+1)*480])for y in range(272)]
    png(stage/'loaded-canvas-RGB565-preview.png',rows,480,272)
    enlarged=[b''.join(pixels[y*480+x]*16 for x in range(310,360))for y in range(170,194)]
    png(stage/'loaded-caption-RGB565-preview.png',[row for row in enlarged for _ in range(16)],800,384)


if __name__=='__main__':main()
