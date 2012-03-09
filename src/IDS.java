import java.io.IOException;
import java.util.List;

import net.sourceforge.jpcap.capture.PacketCapture;

public class IDS
{
	public static void main(String[] args) throws IOException
	{   
		List<Rule> rules = null;
		// Check the arguments.
		if (args.length < 2)
		{
			System.out.println("IDS <pcap file> <rule file>");
			System.exit(0);
		}

		// Parse the Rules file.
		RuleParser parser;
		try {
			parser = new RuleParser(args[1]);
		    rules = parser.parse();

		// Read PCap file.
		PacketCapture capture= new PacketCapture();
		capture.addPacketListener(new IDSPacketListener(rules));
	
			capture.openOffline(args[0]);
			capture.capture(-1);
		}
		catch (Exception exc)
		{
			exc.printStackTrace();
		}
		
		for(int i=0; i< rules.size(); i++){
			System.out.print(i+"| ");
			rules.get(i).print_rules();
		}
	}
}
