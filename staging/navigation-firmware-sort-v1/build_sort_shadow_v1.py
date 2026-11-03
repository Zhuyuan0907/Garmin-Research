#!/usr/bin/env python3
"""Build a bounded shadow Sort prototype; never edits original JAR or resource."""
from pathlib import Path
import hashlib,json
BASE=Path(__file__).resolve().parent
REF=Path('/root/garmin/staging/navigation-search-encoding-v1/reference/Sort.java')
EXPECTED='c9497644d1a3e1067c5ed11da093fcccd4b9382cb949dde431e49fb9c4a75dab'
s=REF.read_text();assert hashlib.sha256(REF.read_bytes()).hexdigest()==EXPECTED
helper='''
	/** Exact finite HWID 1352 / SW 8.00 native implicit Han ranges.
	 * This changes host keys/iterators only, not stored SRT weights or maxPrimary.
	 */
	private int nativeImplicitBase(int c) {
		if (codepage != 65001 || !isMulti()) return 0;
		if (c >= 0x4e00 && c <= 0x9fbb) return 0xfb40;
		if ((c >= 0x3400 && c <= 0x4dbf) || (c >= 0x20000 && c <= 0x2a6d6)) return 0xfb80;
		return 0;
	}

	private int nativeImplicitPosition(int strength, int c, int base, boolean second) {
		if (strength == Collator.PRIMARY)
			return second ? 0x8000 + (c & 0x7fff) : base + (c >>> 15);
		return strength == Collator.SECONDARY ? 0x20 : 2;
	}

	private boolean containsNativeImplicit(char[] chars) {
		for (int i = 0; i < chars.length; i++) {
			int c = Character.codePointAt(chars, i);
			if (nativeImplicitBase(c) != 0) return true;
			if (c > 0xffff) i++;
		}
		return false;
	}
'''
needle='\tprivate int fillKey(int type, char[] input, byte[] outKey, int start) {'
assert s.count(needle)==1;s=s.replace(needle,helper+'\n'+needle)
old='''		for (char c : input) {

			if (!hasPage(c >>> 8)) {'''
new='''		for (int inputPos = 0; inputPos < input.length; inputPos++) {
			int c = input[inputPos];
			int cp = Character.codePointAt(input, inputPos);
			int implicitBase = nativeImplicitBase(cp);
			if (implicitBase != 0) {
				if (cp > 0xffff) inputPos++;
				index = writeSort(type, nativeImplicitPosition(type, cp, implicitBase, false), outKey, index);
				index = writeSort(type, nativeImplicitPosition(type, cp, implicitBase, true), outKey, index);
				continue;
			}

			if (!hasPage(c >>> 8)) {'''
assert s.count(old)==1;s=s.replace(old,new)
old='\t\tbyte[] key = new byte[(chars.length + 1 + 2) * 4];'
new='\t\tint keyBytesPerChar = containsNativeImplicit(chars) ? 8 : 4;\n\t\tbyte[] key = new byte[(chars.length + 1 + 2) * keyBytesPerChar];'
assert s.count(old)==1;s=s.replace(old,new)
old='\t\t\tkey = new byte[(chars.length+1) * 4 * maxExpSize];'
new='\t\t\tkey = new byte[(chars.length+1) * keyBytesPerChar * maxExpSize];'
assert s.count(old)==1;s=s.replace(old,new)
old='\t\t\tprivate int expPos;'
new=old+'\n\t\t\tprivate int pendingImplicitPosition;'
assert s.count(old)==1;s=s.replace(old,new)
old='\t\t\t\treturn pos < len || expPos != 0;'
new='\t\t\t\treturn pos < len || expPos != 0 || pendingImplicitPosition != 0;'
assert s.count(old)==1;s=s.replace(old,new)
old='''			public int next() {
				int next;'''
new='''			public int next() {
				if (pendingImplicitPosition != 0) {
					int result = pendingImplicitPosition;
					pendingImplicitPosition = 0;
					return result;
				}
				int next;'''
assert s.count(old)==1;s=s.replace(old,new)
old='''						int c = chars[pos++];
						if (!hasPage(c >>> 8)) {'''
new='''						int charPos = pos++;
						int c = chars[charPos];
						int cp = Character.codePointAt(chars, charPos);
						int implicitBase = nativeImplicitBase(cp);
						if (implicitBase != 0) {
							if (cp > 0xffff) pos++;
							pendingImplicitPosition = nativeImplicitPosition(type, cp, implicitBase, true);
							return nativeImplicitPosition(type, cp, implicitBase, false);
						}
						if (!hasPage(c >>> 8)) {'''
assert s.count(old)==1;s=s.replace(old,new)
out=BASE/'sort-shadow-src/uk/me/parabola/imgfmt/app/srt/Sort.java';out.parent.mkdir(parents=True,exist_ok=True);out.write_text(s)
receipt={'base_source':str(REF),'base_sha256':EXPECTED,'source_url':'https://www.mkgmap.org.uk/download/mkgmap-r4924-src.zip','shadow_source':str(out),'shadow_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'original_jar_or_resource_modified':False,'SRT_writer_modified':False,'maxPrimary_definitions_modified':False,'prototype_not_map_candidate':True}
(BASE/'sort-shadow-build-source-v1.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
