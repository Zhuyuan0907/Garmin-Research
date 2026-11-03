import java.lang.reflect.*;
import uk.me.parabola.imgfmt.app.srt.SRTFile;
import uk.me.parabola.imgfmt.app.ImgFileWriter;
class PackedGuardFixture {
 public static void main(String[] args)throws Exception{
  Method m=SRTFile.class.getDeclaredMethod("writeMultiWeights",ImgFileWriter.class,int.class,int.class,int.class);m.setAccessible(true);
  int[][] bad={{-1,0,0},{65536,0,0},{1,-1,0},{1,1024,0},{1,0,-1},{1,0,64}};int passed=0;
  for(int[] x:bad){try{m.invoke(null,null,x[0],x[1],x[2]);throw new AssertionError("accepted overflow");}catch(InvocationTargetException e){if(!(e.getCause() instanceof IllegalArgumentException))throw e;passed++;}}
  System.out.println("{\"all_passed\":true,\"hard_overflow_rejections\":"+passed+",\"assertions_enabled\":false,\"valid_emission_verified_separately\":true}");
 }
}
