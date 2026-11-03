import java.io.*;
import java.lang.reflect.*;
class CheckHouseNumberParser {
 public static void main(String[] args)throws Exception {
  Class<?> c=Class.forName("uk.me.parabola.mkgmap.osmstyle.housenumber.HousenumberGenerator");
  Method m=c.getDeclaredMethod("parseHousenumber",String.class);m.setAccessible(true);
  try(var br=new BufferedReader(new InputStreamReader(System.in,"UTF-8"))){
   String s;while((s=br.readLine())!=null)System.out.println(s+"\t"+m.invoke(null,s));
  }
 }
}
