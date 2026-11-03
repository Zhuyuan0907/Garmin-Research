import java.text.Collator;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.*;
import uk.me.parabola.imgfmt.app.srt.Sort;
import uk.me.parabola.imgfmt.app.srt.SRTFile;
import uk.me.parabola.mkgmap.srt.SrtTextReader;
import uk.me.parabola.imgfmt.sys.FileImgChannel;
class ShadowSortFixture {
 static String key(Sort s,String text)throws Exception {
  Object k=s.createSortKey(text,text);
  for(Field f:k.getClass().getDeclaredFields())if(f.getType()==byte[].class){f.setAccessible(true);return HexFormat.of().formatHex((byte[])f.get(k));}
  throw new AssertionError();
 }
 static int intField(Sort s,String name)throws Exception {Field f=Sort.class.getDeclaredField(name);f.setAccessible(true);return f.getInt(s);}
 static String tables(Sort s)throws Exception {
  MessageDigest d=MessageDigest.getInstance("SHA-256");
  for(int p=0;p<256;p++){d.update((byte)(s.hasPage(p)?1:0));if(s.hasPage(p))for(int j=0;j<256;j++){
   int cp=p*256+j;d.update(ByteBuffer.allocate(16).putInt(s.getFlags(cp)).putInt(s.getPrimary(cp)).putInt(s.getSecondary(cp)).putInt(s.getTertiary(cp)).array());
  }}
  for(int i=1;i<=s.getExpansionSize();i++){var x=s.getExpansion(i);d.update(ByteBuffer.allocate(12).putInt(x.getPrimary()).putInt(x.getSecondary()).putInt(x.getTertiary()).array());}
  return HexFormat.of().formatHex(d.digest());
 }
 public static void main(String[] args)throws Exception {
  Sort s=SrtTextReader.sortForCodepage(65001);String before=tables(s);
  System.out.printf("META\t%d\t%d\t%d\t%s%n",intField(s,"maxPrimary"),intField(s,"maxExpSize"),s.getMaxPage(),before);
  for(String text:Files.readAllLines(Path.of(args[0]),StandardCharsets.UTF_8))System.out.println("KEY\t"+text+"\t"+key(s,text));
  for(String row:Files.readAllLines(Path.of(args[1]),StandardCharsets.UTF_8)){
   String[] pair=row.split("\\t",-1);
   for(int strength=0;strength<3;strength++){Collator c=s.getCollator();c.setStrength(strength);System.out.printf("CMP\t%s\t%s\t%d\t%d%n",pair[0],pair[1],strength,c.compare(pair[0],pair[1]));}
  }
  if(!before.equals(tables(s)))throw new AssertionError("keys changed tables");
  var channel=new FileImgChannel(args[2],"rw");var writer=new SRTFile(channel);writer.setSort(s);writer.write();writer.close();channel.close();
  System.out.println("TABLES_AFTER\t"+tables(s));
 }
}
