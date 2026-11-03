import java.text.Collator;
import java.lang.reflect.Field;
import java.util.*;
import uk.me.parabola.imgfmt.app.srt.Sort;
import uk.me.parabola.mkgmap.srt.SrtTextReader;

class SortCounterexample {
 static String key(Sort s, String t) throws Exception {
  Object k=s.createSortKey(t,t);
  for(Field f:k.getClass().getDeclaredFields()) {
   if(f.getType()==byte[].class){f.setAccessible(true);return HexFormat.of().formatHex((byte[])f.get(k));}
  }
  return k.toString();
 }
 public static void main(String[] args)throws Exception {
  String[] names={"民權路","民和路","中山路","臺中市","台中市","台中市西區民權路","臺中市西區民權路","民生路","民權東路","民權西路"};
  for(int cp:new int[]{65001,950}) {
   Sort s=SrtTextReader.sortForCodepage(cp);
   Collator c=s.getCollator();c.setStrength(Collator.SECONDARY);
   System.out.printf("CP %d multi=%s desc=%s id1=%d id2=%d maxpage=%d%n", cp,s.isMulti(),s.getDescription(),s.getId1(),s.getId2(),s.getMaxPage());
   for(String n:names) {
    System.out.printf("name=%s key=%s%n",n,key(s,n));
    for(char ch:n.toCharArray())if(cp==65001)System.out.printf(" char=%c page=%s primary=%s%n",ch,s.hasPage(ch>>>8),s.hasPage(ch>>>8)?s.getPrimary(ch):"implicit");
   }
   for(int i=0;i<names.length;i++)for(int j=i+1;j<names.length;j++) System.out.printf("compare(%s,%s)=%d%n",names[i],names[j],c.compare(names[i],names[j]));
  }
 }
}
