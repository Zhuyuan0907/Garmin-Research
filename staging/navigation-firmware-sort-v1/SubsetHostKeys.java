import java.text.Collator;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import uk.me.parabola.imgfmt.app.srt.Sort;
import uk.me.parabola.mkgmap.srt.SrtTextReader;
class SubsetHostKeys {
 public static void main(String[] args) throws Exception {
  Sort s=SrtTextReader.sortForCodepage(65001);
  Collator c=s.getCollator();c.setStrength(Collator.SECONDARY);
  for(String name:Files.readAllLines(Path.of(args[0]),StandardCharsets.UTF_8)) {
   Object k=s.createSortKey(name,name);byte[] key=null;
   for(Field f:k.getClass().getDeclaredFields())if(f.getType()==byte[].class){f.setAccessible(true);key=(byte[])f.get(k);}
   if(key==null)throw new AssertionError();
   System.out.println(name+"\t"+HexFormat.of().formatHex(key));
  }
 }
}
