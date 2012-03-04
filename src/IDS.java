import java.util.List;

import net.sourceforge.jpcap.capture.PacketCapture;

public class IDS
{
	public static void main(String[] args)
	{
		// Check the arguments.
		if (args.length < 2)
		{
			System.out.println("IDS <pcap file> <rule file>");
			System.exit(0);
		}

		// Parse the Rules file.
		RuleParser parser = new RuleParser(args[1]);
		List<Rule> rules = parser.parse();

		// Read PCap file.
		PacketCapture capture= new PacketCapture();
		capture.addPacketListener(new IDSPacketListener(rules));
		try
		{
			capture.openOffline(args[0]);
			capture.capture(-1);
		}
		catch (Exception exc)
		{
			exc.printStackTrace();
		}
	}
}
