import java.util.*;
import uk.me.parabola.imgfmt.app.map.MapReader;
import uk.me.parabola.imgfmt.app.trergn.*;

class ReadRenderingStats {
 static String q(String s){ return "\""+s.replace("\\","\\\\").replace("\"","\\\"")+"\""; }
 public static void main(String[] args)throws Exception {
  System.out.println("["); boolean comma=false;
  for(String file:args)try(MapReader m=new MapReader(file)){
   for(Zoom z:m.getLevels()){
    var pts=m.pointsForLevel(z.getLevel(),true);
    var lines=m.linesForLevel(z.getLevel());
    var shapes=m.shapesForLevel(z.getLevel(),true);
    int subs=0; for(var it=z.subdivIterator();it.hasNext();){it.next();subs++;}
    long lv=0,sv=0,buildings=0,bv=0,sea=0,seav=0,bg=0,bgv=0;
    TreeMap<Integer,Integer> shapeTypes=new TreeMap<>();
    for(Polyline p:lines)lv+=p.getPoints().size();
    for(Polygon p:shapes){
     int t=p.getType(),n=p.getPoints().size(); sv+=n;
     shapeTypes.merge(t,1,Integer::sum);
     if(t==0x13){buildings++;bv+=n;}
     if(t==0x32){sea++;seav+=n;}
     if(t==0x4b){bg++;bgv+=n;}
    }
    if(comma)System.out.println(",");comma=true;
    System.out.print("{\"file\":"+q(file)+",\"level\":"+z.getLevel()+",\"resolution\":"+z.getResolution()+",\"subdivisions\":"+subs+",\"points\":"+pts.size()+",\"line_records\":"+lines.size()+",\"line_vertices\":"+lv+",\"polygon_records\":"+shapes.size()+",\"polygon_vertices\":"+sv+",\"building_type_0x13_records\":"+buildings+",\"building_type_0x13_vertices\":"+bv+",\"sea_type_0x32_records\":"+sea+",\"sea_type_0x32_vertices\":"+seav+",\"background_type_0x4b_records\":"+bg+",\"background_type_0x4b_vertices\":"+bgv+",\"polygon_type_counts\":{");
    boolean c=false;for(var e:shapeTypes.entrySet()){if(c)System.out.print(",");c=true;System.out.print(q(String.format("0x%X",e.getKey()))+":"+e.getValue());}
    System.out.print("}}");
   }
  }
  System.out.println("\n]");
 }
}
