#!/usr/bin/env python3
"""Small successor source set: implicit Han host Sort + native 16/10/6 SRT writer."""
from pathlib import Path
import hashlib,json
BASE=Path(__file__).resolve().parent
WRITER=Path('/root/garmin/staging/navigation-search-encoding-v1/writer-patch-src/uk/me/parabola/imgfmt/app/srt/SRTFile.java')
EXPECTED='98b3a515c11c8eedcc3374ae5ffff56e343d856e5f615d24717bc12f40126b68'
assert hashlib.sha256(WRITER.read_bytes()).hexdigest()==EXPECTED
lines=(BASE/'packed-fixture-original-v2.tsv').read_text().splitlines();maxima=next(x for x in lines if x.startswith('MAXIMA')).split('\t')[1:];vals=[int(x) for x in maxima];assert vals==[255,20,8,8];assert vals[0]<=1023 and vals[1]<=63 and vals[2]<=1023 and vals[3]<=63
s=WRITER.read_text()
old='''			assert primary <= 0xffff : primary;
			assert secondary <= 0xff : secondary;
			assert tertiary <= 0xff : tertiary;
			writer.put2u(primary);
			writer.put1u(secondary);
			writer.put1u(tertiary);'''
new='\t\t\twriteMultiWeights(writer, primary, secondary, tertiary);'
assert s.count(old)==1;s=s.replace(old,new)
old='''				writer.put2u(b.getPrimary());
				writer.put1u(b.getSecondary());
				writer.put1u(b.getTertiary());'''
new='\t\t\t\twriteMultiWeights(writer, b.getPrimary(), b.getSecondary(), b.getTertiary());'
assert s.count(old)==1;s=s.replace(old,new)
helper='''
	/** HWID 1352 SW 8.00 flag 0x4000 selects 16/10/6 packed weights.
	 * Hard guards apply even when Java assertions are disabled.
	 */
	private static void writeMultiWeights(ImgFileWriter writer, int primary, int secondary, int tertiary) {
		if (primary < 0 || primary > 0xffff || secondary < 0 || secondary > 0x3ff || tertiary < 0 || tertiary > 0x3f)
			throw new IllegalArgumentException("SRT 16/10/6 weight overflow");
		writer.put2u(primary);
		writer.put2u(secondary | (tertiary << 10));
	}
'''
needle='\tprivate void writeSrt5Expansions(ImgFileWriter writer) {';assert s.count(needle)==1;s=s.replace(needle,helper+'\n'+needle)
out=BASE/'packed-shadow-src-v2/uk/me/parabola/imgfmt/app/srt';out.mkdir(parents=True,exist_ok=True);out.joinpath('SRTFile.java').write_text(s);sort=(BASE/'sort-shadow-src/uk/me/parabola/imgfmt/app/srt/Sort.java').read_bytes();out.joinpath('Sort.java').write_bytes(sort)
receipt={'source_url':'https://www.mkgmap.org.uk/download/mkgmap-r4924-src.zip','writer_base_sha256':EXPECTED,'shadow_sources':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in out.glob('*.java')},'original_defined_max_secondary':vals[0],'original_defined_max_tertiary':vals[1],'original_expansion_max_secondary':vals[2],'original_expansion_max_tertiary':vals[3],'limits':{'secondary':1023,'tertiary':63},'hard_guards_not_assert_only':True,'header_flags_changed':False,'writer_retains_previous_missing_BMP_page_materialization':True,'original_JAR_resource_firmware_candidate_modified':False,'prototype_only':True}
(BASE/'packed-shadow-source-receipt-v2.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
