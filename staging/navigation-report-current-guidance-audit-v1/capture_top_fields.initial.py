"""Read two explicitly authorized 4KiB top JSON prefixes, no full state scans."""
from pathlib import Path
import hashlib,json,os,stat
HERE=Path(__file__).resolve().parent;ROOT=Path('/root/garmin')
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def first_pairs(raw):
    # Decode complete top-level values only; halt at the first truncated value.
    s=raw.decode('utf-8');d=json.JSONDecoder();i=0;out={}
    while s[i].isspace():i+=1
    assert s[i]=='{';i+=1
    while i<len(s):
        while i<len(s) and (s[i].isspace() or s[i]==','):i+=1
        if i>=len(s) or s[i]=='}':break
        try:
            key,i=d.raw_decode(s,i)
            while s[i].isspace():i+=1
            assert s[i]==':';i+=1
            while s[i].isspace():i+=1
            value,i=d.raw_decode(s,i)
        except (json.JSONDecodeError,IndexError):break
        out[key]=value
    return out
def main():
    rows=[]
    for path,label,key in [('evidence/task-state.json','task-state-top-prefix.bin','user_away'),
                           ('reports/findings.json','findings-top-prefix.bin','research_goal_status')]:
        p=ROOT/path;b=p.stat();assert stat.S_ISREG(b.st_mode)
        with p.open('rb') as f:raw=f.read(4096)
        a=p.stat();assert fp(a)==fp(b) and len(raw)==4096
        fd=os.open(HERE/'private-inputs'/label,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw)
        fields=first_pairs(raw)
        rows.append(dict(source=path,read_range=[0,len(raw)],file_bytes=b.st_size,
            prefix_sha256=hashlib.sha256(raw).hexdigest(),stat_before=fp(b),stat_after=fp(a),
            mode=format(stat.S_IMODE(a.st_mode),'04o'),requested_top_key=key,
            top_key_found=key in fields,actual_top_value=fields.get(key),whole_file_hash_not_read=True))
    result=dict(schema='garmin-report-audit-top-prefix/v1',actual_additional_bytes=8192,
        total_original_artifact_bytes=419847+8192,cap=786432,rows=rows,all_handles_closed=True)
    (HERE/'top-field-read-receipts.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(additional_bytes=8192,fields=[(r['source'],r['requested_top_key'],r['top_key_found'],r['actual_top_value']) for r in rows])))
if __name__=='__main__':main()
