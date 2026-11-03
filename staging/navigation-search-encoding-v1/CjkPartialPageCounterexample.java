import java.text.Collator;
import uk.me.parabola.imgfmt.app.srt.Sort;
import uk.me.parabola.mkgmap.srt.SrtTextReader;
class CjkPartialPageCounterexample {public static void main(String[]a){Sort s=SrtTextReader.sortForCodepage(65001);Collator c=s.getCollator();c.setStrength(Collator.SECONDARY);String[]x={"\u4d00路","\u4d01路"};System.out.printf("page4Dpresent=%s primary4D00=%d primary4D01=%d compare=%d%n",s.hasPage(0x4d),s.getPrimary(0x4d00),s.getPrimary(0x4d01),c.compare(x[0],x[1]));System.out.printf("keyCompare=%d%n",s.createSortKey(x[0],x[0]).compareTo(s.createSortKey(x[1],x[1])));}}
