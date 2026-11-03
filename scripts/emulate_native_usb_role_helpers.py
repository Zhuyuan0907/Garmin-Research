#!/usr/bin/env python3
"""Execute stock extension-control/probe/test helpers on synthetic registers.

No actual USB role, voltage, ADC, UART, device, or controller model. Timer/status
fixtures supply values immediately before the original loads, not replacement
functions. The meaning of the extension control register remains unknown.
"""
from datetime import datetime,timezone
import hashlib,json,re,struct,sys
from pathlib import Path
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R4,UC_ARM_REG_CPSR
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_native_projection_io import Probe,USB,require

CONTROL,GATE,FLAG,TIMER=USB+0x204,0x101e9000,0xf08e0b,0x101e3044
BANKS={0:0x101fd000,1:0x101fb000,3:0x101fe000}

def sha(name):return hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
def reference_packet():
    source=(ROOT/'sources/native-usb/musb_core.c').read_text()
    body=re.search(r'static const u8 musb_test_packet\[53\]\s*=\s*\{(.*?)\};',source,re.S).group(1)
    body=re.sub(r'/\*.*?\*/','',body,flags=re.S)
    values=bytes(int(n,16) for n in re.findall(r'0x([0-9a-fA-F]+)',body))
    require(len(values)==53,'Primary reference packet length differs')
    return values

class RoleProbe(Probe):
    def __init__(self,stock):
        super().__init__(stock)
        self.stock=stock;self.writes=[];self.timer_events=[];self.status_events=[]
        self.timer_values={};self.status_values={}
        for base in [GATE,TIMER&~4095,*BANKS.values()]:self.uc.mem_map(base,4096)
        self.uc.hook_add(UC_HOOK_MEM_WRITE,self.record_write)
    def record_write(self,uc,access,address,size,value,user):
        if USB<=address<USB+4096 or GATE<=address<GATE+4096 or any(b<=address<b+4096 for b in BANKS.values()):
            self.writes.append({'address':hex(address),'bytes':size,'value':value})
    def observe(self,uc,address,size,user):
        if address in self.timer_values:
            sequence=self.timer_values[address];require(sequence,'Timer fixture exhausted')
            value=sequence.pop(0);self.put(TIMER,value)
            self.timer_events.append({'original_load':hex(address),'synthetic_timer':value})
        if address in self.status_values:
            target=uc.reg_read(UC_ARM_REG_R4)+4
            require(target in [b+0x84 for b in BANKS.values()],'Status probe left selected bank')
            value=self.status_values[address];self.put(target,value)
            self.status_events.append({'original_load':hex(address),'register':hex(target),'synthetic_status':value})
        super().observe(uc,address,size,user)
    def code_intact(self):
        for start,end in [(0x1bb018,0x1bb0c0),(0x1bfc42,0x1bfcde),(0x21b6cc,0x21b6ec)]:
            original=self.stock.read(self.stock.runtime_to_load(start,end-start),end-start)
            require(self.data(start,end-start)==original,'Original helper code changed')
        require(not self.fixtures,'Unexpected function fixture')
        return True

def main():
    stock=NativeImage();packet=reference_packet();cases=[]
    require(stock.read(0x8e0aec,53)==packet,'Stock test packet differs from primary reference')
    def record(name,p,**detail):
        require(not any(USB+0x60<=int(r['address'],16)<USB+0x61 for r in p.writes),'Unexpected DEVCTL write')
        cases.append({'name':name,'all_passed':True,'original_code_intact':p.code_intact(),
          'synthetic_register_writes':p.writes,'timer_fixture_events':p.timer_events,
          'status_fixture_events':p.status_events,'function_fixtures':[],**detail})
    for old in (0,0xffffffff,0x5a5a93c5):
        for flag in (0,1):
            for selector in range(4):
                p=RoleProbe(stock);p.put(CONTROL,old);p.put(GATE,0x13579bdf)
                p.uc.mem_write(FLAG,bytes((flag,)))
                p.call(0x1bb018,1,selector)
                expected=((old|0x4000|(0x2000 if flag else 0))&~0x18000)|(selector<<15)
                require(p.word(CONTROL)==expected,'Original extension enable/selector fields differ')
                require(p.word(GATE)==(0x13579bdf|8),'Original separate gate bit differs')
                require(p.call(0x1bb05e)==1,'Original bit14 getter differs')
                record(f'extension_enable_{old:x}_flag{flag}_selector{selector}',p,
                  input_control=old,input_flag=flag,input_selector=selector,output_control=expected,
                  bit13_is_set_conditionally_not_cleared_when_flag_zero=True)
        p=RoleProbe(stock);p.put(CONTROL,old);p.put(GATE,0x2468ace0)
        p.call(0x1bb018,0,3)
        require(p.word(CONTROL)==old&~0x4000 and p.word(GATE)==0x2468ace0,'Disable changed unrelated state')
        require(p.call(0x1bb05e)==0,'Original disabled getter differs')
        record(f'extension_disable_{old:x}',p,only_bit14_cleared=True,separate_gate_not_cleared=True)
    for channel,bank in BANKS.items():
        for toggle in (0,1):
            for first,second in ((0,0),(1,1),(1,0)):
                p=RoleProbe(stock);p.put(bank+0x80,0xa5a5a5a4);p.put(CONTROL,0x53aa92c5)
                p.put(GATE,0x12345670);p.uc.mem_write(FLAG,b'\x01')
                p.timer_values={0x1bfc90:[1000],0x1bfc92:[998,996]}
                p.status_values={0x1bfc9a:first}
                if first:
                    p.timer_values.update({0x1bfca8:[900],0x1bfcaa:[899,898]})
                    p.status_values[0x1bfcb2]=second
                before=p.uc.reg_read(UC_ARM_REG_CPSR)
                result=p.call(0x1bfc5e,channel,toggle)
                require(result==int(first==1 and second==0),'Original two-sample probe result differs')
                require(p.word(bank+0x80)==0xa5a5a5a4,'Probe control bit0 not restored')
                require(p.word(bank+0x88)==1,'Probe output pulse final value differs')
                require((before&0xc0)==(p.uc.reg_read(UC_ARM_REG_CPSR)&0xc0),'IRQ mask not restored')
                require(p.visits[0x21b6cc]==p.visits[0x21b6dc]==1,'Original IRQ helpers bypassed')
                require(p.visits[0x1bb018]==2*toggle,'Temporary extension toggle calls differ')
                expected=((0x53aa92c5|0x2000)&~0x18000&~0x4000)|(channel<<15) if toggle else 0x53aa92c5
                require(p.word(CONTROL)==expected,'Probe extension final state differs')
                require(all(not q for q in p.timer_values.values()),'Timer path skipped')
                record(f'sample_probe_channel{channel}_toggle{toggle}_{first}{second}',p,
                  bank=hex(bank),native_result=result,IRQ_mask_restored=True,
                  previous_extension_control_not_fully_restored=bool(toggle))
    for channel in (2,4):
        p=RoleProbe(stock);result=p.call(0x1bfc5e,channel,1)
        require(result==0 and not p.writes and not p.visits[0x1bb018],'Unsupported bank accessed registers')
        record(f'unsupported_probe_bank_{channel}',p,native_result=result)
    for selector,mode in ((1,2),(2,4),(3,1),(4,8),(0,None),(128,None)):
        p=RoleProbe(stock);p.uc.mem_write(USB+0xf,b'\x55');p.uc.mem_write(USB+0x12,struct.pack('<H',0x0401))
        p.call(0x1bb068,selector)
        values=[r['value'] for r in p.writes if r['address']==hex(USB+0x20)]
        require(p.data(USB+0xe,1)==b'\x00','Test helper did not select EP0')
        require(p.data(USB+0xf,1)==bytes((0x55 if mode is None else mode,)),'Original TESTMODE mapping differs')
        require(bytes(values)==(packet if selector==4 else b''),'Electrical test FIFO bytes differ')
        expected=0x0401|0x20|(0xa if selector==4 else 0)
        require(p.data(USB+0x12,2)==struct.pack('<H',expected),'Test CSR word differs')
        record(f'electrical_test_selector_{selector}',p,testmode_value=mode,
          test_FIFO_bytes=len(values),exact_primary_53byte_pattern=selector==4,
          force_host_bit80_not_selected=True)
    deps={Path(__file__).resolve(),ROOT/'evidence/firmware-analysis/main_02bd.bin',
      ROOT/'sources/native-usb/source-snapshots.json',ROOT/'sources/native-usb/musb_core.c',ROOT/'sources/native-usb/musb_regs.h'}
    for module in list(sys.modules.values()):
        name=getattr(module,'__file__',None)
        if name and Path(name).resolve().parent==ROOT/'scripts' and name.endswith('.py'):deps.add(Path(name).resolve())
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
      'all_passed':True,'case_count':len(cases),'cases':cases,
      'source_sha256':{str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT))) for p in sorted(deps)},
      'stock_code_mappings_write_protected':True,
      'original_extension_control':'0x10200204','extension_control_register_physical_meaning_verified':False,
      'temporary_probe_does_not_restore_all_extension_fields':True,
      'test_packet_sha256':hashlib.sha256(packet).hexdigest(),
      'test_packet_exact_primary_match':True,'timer_and_status_loads_are_fixtures':True,
      'physical_chip_identity_USB_host_UART_ADC_VBUS_or_phone_verified':False,
      'device_io':False,'firmware_modified':False,'device_install_candidate':False,
      'scope':'Stock extension control/getter, peripheral-bank selection and temporary two-sample probe, '
        'original IRQ save/restore and electrical-test helper executed against synthetic register RAM. '
        'Timer and probe-status values inserted before original loads; no function replacements. '
        '53-byte test pattern matches primary Linux reference, not AOA setup or USB host evidence. '
        'Unknown extension-control meaning, unmodelled register/FIFO side effects, no live hardware '
        'identity/role/VBUS, calibration, UART/ADC/DMA, actual electrical tests, phone or installed native App.'}
    name='evidence/firmware-analysis/native-usb-role-helpers-emulation.json'
    (ROOT/name).write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':name,'cases':len(cases),'dependencies':len(deps),'test_packet_primary_match':True,'device_io':False}))
if __name__=='__main__':main()
