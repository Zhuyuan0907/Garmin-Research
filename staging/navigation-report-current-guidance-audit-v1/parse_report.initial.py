"""Parse owned HTML snapshot, retaining DOM context for every body text block."""
from html.parser import HTMLParser
from pathlib import Path
import hashlib,json,re
HERE=Path(__file__).resolve().parent
KEYWORDS=re.compile(r'目前|最新|下一步|待實機|v3|尚未實機|實機接受|兩圖層|兩層|只勾|待測試',re.I)
BLOCKS={'p','li','td','th','dd','dt','blockquote','figcaption','summary'}
VOID={'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}
def compact(s):return re.sub(r'\s+',' ',s).strip()
def redact(s):
    s=re.sub(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}','[private-device-id]',s)
    s=re.sub(r'/(?:root|media|run/media|mnt)/[^\s<>"\u3000，；。]*','[private-local-path]',s)
    return s
class Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True);self.stack=[];self.roots={};self.rows=[];self.headings={};self.n=0
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs);counts=self.stack[-1]['counts'] if self.stack else self.roots
        counts[tag]=counts.get(tag,0)+1
        part=tag+('#'+attrs['id'] if attrs.get('id') else '['+str(counts[tag])+']')
        frame=dict(tag=tag,attrs=attrs,part=part,counts={},text=[],line=self.getpos()[0],
            heading_context=dict(self.headings),ancestors=[x['attrs'].get('id') for x in self.stack if x['attrs'].get('id')],
            selector=' > '.join([x['part'] for x in self.stack]+[part]),body=any(x['tag']=='body' for x in self.stack))
        if tag not in VOID:self.stack.append(frame)
    def handle_startendtag(self,tag,attrs):self.handle_starttag(tag,attrs);self.handle_endtag(tag)
    def handle_data(self,data):
        if any(x['tag'] in ('script','style') for x in self.stack):return
        for f in self.stack:f['text'].append(data)
    def handle_endtag(self,tag):
        matches=[i for i,f in enumerate(self.stack) if f['tag']==tag]
        if not matches:return
        idx=matches[-1];frames=self.stack[idx:];self.stack=self.stack[:idx]
        for f in reversed(frames):
            text=compact(''.join(f['text']))
            if f['tag'] in ('h1','h2','h3','h4','h5','h6') and text:
                level=int(f['tag'][1]);self.headings={k:v for k,v in self.headings.items() if int(k[1])<level}
                self.headings[f['tag']]=redact(text)
            if f['body'] and f['tag'] in BLOCKS and text:
                self.n+=1
                self.rows.append(dict(paragraph_id=self.n,selector=f['selector'],html_line=f['line'],
                    tag=f['tag'],enclosing_ids=f['ancestors'],heading_context=f['heading_context'],
                    text_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    selected=bool(KEYWORDS.search(text)),redacted_text=redact(text),
                    keyword_matches=sorted(set(KEYWORDS.findall(text)))))
def main():
    p=Parser();raw=(HERE/'private-inputs/report.html').read_bytes();p.feed(raw.decode('utf-8'));p.close()
    (HERE/'parsed-paragraphs.private.json').write_text(json.dumps(p.rows,ensure_ascii=False,indent=2)+'\n')
    selected=[r for r in p.rows if r['selected']]
    print(json.dumps(dict(total_body_blocks=len(p.rows),keyword_selected_blocks=len(selected),
        web_top_keys=list(json.loads((HERE/'private-inputs/web.json').read_text()).keys())),ensure_ascii=False))
    for r in selected:
        print(str(r['paragraph_id'])+' '+str(r['html_line'])+' '+str(r['heading_context'])+' '+r['redacted_text'][:310])
if __name__=='__main__':main()
