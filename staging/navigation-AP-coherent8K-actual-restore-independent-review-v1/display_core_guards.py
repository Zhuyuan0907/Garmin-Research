"""Second static display of two sources, fully accounted under160KiB."""
from pathlib import Path
import ast,hashlib,json
HERE=Path(__file__).resolve().parent
PATHS=[('staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/eightk_inverse_header_overlay.py',
 '284b164a568edaca06707b572f0dd1f4bd2d96b913546adb56e7a99979480dbc'),
 ('staging/navigation-country-address-package-v3/native_8k_stock_restore.py',
 '43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f')]
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def main():
    receipts=[]
    for index,(name,pin) in enumerate(PATHS):
        p=Path(name);b=p.stat()
        with p.open('rb') as f:raw=f.read(b.st_size+1)
        a=p.stat();assert fp(a)==fp(b) and len(raw)==b.st_size and hashlib.sha256(raw).hexdigest()==pin
        receipts.append(dict(path=name,bytes=len(raw),sha256=pin,stat_before=fp(b),stat_after=fp(a)))
        text=raw.decode();tree=ast.parse(text);lines=text.splitlines()
        print('SOURCE '+name)
        for n in tree.body:
            if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and (index==0 or n.name in
               ['parse_layout','_expected_header','_layouts_and_header','identity','restored_stock_blocks','_restored_blocks']):
                print('LINES '+str(n.lineno)+'..'+str(n.end_lineno)+'\n'+'\n'.join(lines[n.lineno-1:n.end_lineno]))
    (HERE/'second-display-read-receipts.json').write_text(json.dumps(dict(
        reason='First all-source output truncated; necessary fixed adapter/helper guard display',
        additional_source_bytes=sum(r['bytes'] for r in receipts),actual_total_input_bytes=152275,
        cap=163840,reads=receipts,all_handles_closed=True,producer_import_or_execution=False,
        IMG_stat_open_or_read=0),separators=(',',':'))+'\n')
    print('ACTUAL_TOTAL_INPUT_BYTES 152275')
if __name__=='__main__':main()
