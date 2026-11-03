import java.util.*;
import uk.me.parabola.imgfmt.app.map.MapReader;
import uk.me.parabola.imgfmt.app.net.RoadDef;
import uk.me.parabola.imgfmt.app.lbl.City;
import uk.me.parabola.imgfmt.app.Label;
class ReadRoadIndexV2 {
 static Map<String,String> pointNames=new HashMap<>();
 static String q(String s){if(s==null)return "null"; return "\""+s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r")+"\"";}
 static String city(City c){return "{\"name\":"+q(c.getName()==null || c.getName().isEmpty()?pointNames.get(c.getSubdivNumber()+":"+c.getPointIndex()):c.getName())+",\"index\":"+c.getIndex()+",\"regionIndex\":"+c.getRegionNumber()+",\"countryIndex\":"+c.getCountryNumber()+",\"subdivision\":"+c.getSubdivNumber()+",\"pointIndex\":"+c.getPointIndex()+"}";}
 public static void main(String[] args)throws Exception {
  System.out.println("["); boolean comma=false;
  for(String file:args) try(MapReader m=new MapReader(file)) {
   pointNames.clear();
   for(var z:m.getLevels())for(var pt:m.pointsForLevel(z.getLevel(),false))pointNames.put(pt.getSubdiv().getNumber()+":"+pt.getNumber(),pt.getLabel().getText());
   for(RoadDef r: m.getRoads()) {
    List<String> labels=new ArrayList<>();boolean target=false;
    for(Label l:r.getLabels()) if(l!=null) {String s=l.getText();labels.add(q(s));if(s.contains("民權路")||s.contains("民和路")) target=true;}
    if(!target)continue;
    if(comma)System.out.println(",");comma=true;
    List<String> cities=new ArrayList<>(); if(r.getCities()!=null)for(City c:r.getCities())cities.add(city(c));
    System.out.print("{\"file\":"+q(file)+",\"netOffset\":"+r.getOffsetNet1()+",\"id\":"+r.getId()+",\"labels\":["+String.join(",",labels)+"],\"houseNumbersParsingSupportedByReader\":false,\"cities\":["+String.join(",",cities)+"]}");
   }
  }
  System.out.println("\n]");
 }
}
