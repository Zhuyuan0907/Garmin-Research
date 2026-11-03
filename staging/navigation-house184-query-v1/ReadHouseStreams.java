import java.io.*;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.*;
import func.lib.NumberReader;
import uk.me.parabola.imgfmt.app.BitReader;
import uk.me.parabola.imgfmt.app.net.Numbers;

/** Decode only supplied bounded NET number streams with the official r4924 test reader. */
public class ReadHouseStreams {
  public static void main(String[] args) throws Exception {
    NumberReader known = new NumberReader(new BitReader(new byte[]{0x41,0x13,0x27,0x49,0x60}));
    known.setNumberOfNodes(1);
    var control = known.readNumbers(true);
    if(control.size()!=1 || !control.get(0).toString().equals("0,E,24,8,O,23,13"))
      throw new AssertionError("Official NumberPreparerTest known stream failed");
    System.out.println("CONTROL\t0,E,24,8,O,23,13\tpassed");
    Field counter = NumberReader.class.getDeclaredField("nodeCounter");counter.setAccessible(true);
    try(var input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8))) {
      String row;
      while((row=input.readLine())!=null) {
        String[] f=row.split("\t",-1);
        if(f.length!=5) throw new AssertionError("Input shape");
        byte[] data=HexFormat.of().parseHex(f[4]);
        if(data.length==0 || data.length>4096) throw new AssertionError("Bounded number stream");
        int nodes=Integer.parseInt(f[2]);
        if(nodes<1 || nodes>1023)throw new AssertionError("NET node bound");
        BitReader bits=new BitReader(data);NumberReader reader=new NumberReader(bits);
        reader.setNumberOfNodes(nodes);
        // The official test reader catches stream-end/unknown-command exceptions.
        // Capture its diagnostic instead of hiding partial-decode limitations.
        var diagnostics=new ByteArrayOutputStream();PrintStream original=System.out;
        List<Numbers> numbers;
        try(var capture=new PrintStream(diagnostics,true,StandardCharsets.UTF_8)) {
          System.setOut(capture);
          try {numbers=reader.readNumbers(f[3].equals("1"));}
          finally {System.setOut(original);}
        }
        List<String> specs=new ArrayList<>();for(Numbers n:numbers)specs.add(
          n.getIndex()+","+n.getLeftNumberStyle()+","+n.getLeftStart()+","+n.getLeftEnd()+","+
          n.getRightNumberStyle()+","+n.getRightStart()+","+n.getRightEnd());
        System.out.println("STREAM\t"+f[0]+"\t"+f[1]+"\t"+nodes+"\t"+
          counter.getInt(reader)+"\t"+bits.getBitPosition()+"\t"+
          Base64.getEncoder().encodeToString(diagnostics.toByteArray())+"\t"+String.join(";",specs));
      }
    }
  }
}
