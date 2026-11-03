#!/usr/bin/env python3
"""Lossless RGB565 preview of captured native canvas; not a device screenshot."""
from pathlib import Path
import struct
from preview_native_canvas import png
from analyze_native_sections import ROOT

def main():
    stage=ROOT/'staging/native-player-resources';raw=(stage/'loaded-canvas.bin').read_bytes()
    assert len(raw)==480*272*2;values=struct.unpack('<130560H',raw)
    pixels=[bytes((((v>>11)&31)*255//31,((v>>5)&63)*255//63,(v&31)*255//31))for v in values]
    png(stage/'loaded-canvas-RGB565-preview.png',[b''.join(pixels[y*480:(y+1)*480])for y in range(272)],480,272)
    scale=5;rows=[b''.join(pixels[y*480+x]*scale for x in range(288,384))for y in range(146,219)]
    png(stage/'loaded-player-RGB565-preview.png',[row for row in rows for _ in range(scale)],480,365)

if __name__=='__main__':main()
