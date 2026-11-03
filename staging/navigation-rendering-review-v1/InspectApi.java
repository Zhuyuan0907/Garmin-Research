class InspectApi {
 public static void main(String[] args) throws Exception {
  for (String name : args) {
   Class<?> c=Class.forName(name);
   System.out.println(c);
   for (var m:c.getMethods()) if (m.getDeclaringClass()!=Object.class) System.out.println(m);
  }
 }
}
