import java.lang.reflect.*;
class InspectMapApi {
 public static void main(String[] args) throws Exception {
  for(String name: args) {
   Class<?> c=Class.forName(name);System.out.println("CLASS "+name);
   for(Constructor<?> x:c.getDeclaredConstructors()) System.out.println(x);
   for(Method x:c.getDeclaredMethods()) System.out.println(x);
   for(Field x:c.getDeclaredFields()) System.out.println(x);
  }
 }
}
