import uk.me.parabola.imgfmt.app.srt.Sort;
import uk.me.parabola.mkgmap.srt.SrtTextReader;
class CjkCoverage {public static void main(String[]a){Sort s=SrtTextReader.sortForCodepage(65001);for(int p=0x34;p<=0x9f;p++)if(s.hasPage(p))System.out.printf("Existing CJK page %02x%n",p);for(int p=0xf9;p<=0xfa;p++)System.out.printf("Compat page %02x=%s%n",p,s.hasPage(p));}}
