import java.util.*;
import uk.me.parabola.imgfmt.app.map.MapReader;
import uk.me.parabola.imgfmt.app.net.RoadDef;
import uk.me.parabola.imgfmt.app.lbl.*;
import uk.me.parabola.imgfmt.app.Label;
import uk.me.parabola.imgfmt.app.trergn.*;

class ReadRoadGeometryV2 {
 static Map<String,String> pointNames=new HashMap<>();
 static Map<Integer,Region> regions=new HashMap<>();
 static Map<Integer,Country> countries=new HashMap<>();
 static String q(String s){
  if(s==null)return "null";
  StringBuilder b=new StringBuilder("\"");
  for(char c:s.toCharArray()){
   if(c=='"'||c=='\\')b.append('\\').append(c);
   else if(c<32)b.append(String.format("\\u%04x",(int)c));
   else b.append(c);
  }
  return b.append('"').toString();
 }
 static String city(City c){
  String name=c.getName();if(name==null||name.isEmpty())name=pointNames.get(c.getSubdivNumber()+":"+c.getPointIndex());
  Region r=regions.get(c.getRegionNumber());Country k=r==null?countries.get(c.getCountryNumber()):r.getCountry();
  return "{\"name\":"+q(name)+",\"index\":"+c.getIndex()+",\"region\":"+q(r==null?null:r.getLabel().getText())+",\"country\":"+q(k==null?null:k.getLabel().getText())+",\"regionIndex\":"+c.getRegionNumber()+",\"countryIndex\":"+c.getCountryNumber()+",\"subdivision\":"+c.getSubdivNumber()+",\"pointIndex\":"+c.getPointIndex()+"}";
 }
 public static void main(String[] args)throws Exception {
  System.out.println("[");boolean comma=false;
  for(String file:args)try(MapReader m=new MapReader(file)){
   pointNames.clear();regions.clear();countries.clear();
   int detailedLevel=-1,highestResolution=-1;
   for(Zoom z:m.getLevels()){
    if(z.getResolution()>highestResolution){highestResolution=z.getResolution();detailedLevel=z.getLevel();}
    for(Point pt:m.pointsForLevel(z.getLevel(),false))pointNames.put(pt.getSubdiv().getNumber()+":"+pt.getNumber(),pt.getLabel().getText());
   }
   for(Region r:m.getRegions())if(r!=null)regions.put(r.getIndex(),r);
   for(Country c:m.getCountries())if(c!=null)countries.put(c.getIndex(),c);
   Map<Integer,RoadDef> target=new HashMap<>();
   for(RoadDef r:m.getRoads())for(Label l:r.getLabels())if(l!=null&&l.getText().equals("敦富六街"))target.put(r.getOffsetNet1(),r);
   Map<Integer,List<String>> segments=new HashMap<>();
   for(Polyline line:m.linesForLevel(detailedLevel)){
    if(!line.isRoad()||!target.containsKey(line.getOffsetNet1()))continue;
    List<String> coords=new ArrayList<>();for(var c:line.getPoints())coords.add("["+c.getLatDegrees()+","+c.getLonDegrees()+"]");
    segments.computeIfAbsent(line.getOffsetNet1(),k->new ArrayList<>()).add("["+String.join(",",coords)+"]");
   }
   for(var entry:target.entrySet()){
    RoadDef r=entry.getValue();List<String> labels=new ArrayList<>(),cities=new ArrayList<>();
    for(Label l:r.getLabels())if(l!=null)labels.add(q(l.getText()));
    if(r.getCities()!=null)for(City c:r.getCities())cities.add(city(c));
    if(comma)System.out.println(",");comma=true;
    System.out.print("{\"file\":"+q(file)+",\"netOffset\":"+r.getOffsetNet1()+",\"readerIdNotOsmWayId\":"+r.getId()+",\"labels\":["+String.join(",",labels)+"],\"cities\":["+String.join(",",cities)+"],\"geometryZoomLevel\":"+detailedLevel+",\"geometryResolution\":"+highestResolution+",\"segments\":["+String.join(",",segments.getOrDefault(entry.getKey(),new ArrayList<>()))+"]}");
   }
  }
  System.out.println("\n]");
 }
}
