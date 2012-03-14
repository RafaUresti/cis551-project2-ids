import java.util.List;

import net.sourceforge.jpcap.capture.PacketListener;
import net.sourceforge.jpcap.net.Packet;
import net.sourceforge.jpcap.net.TCPPacket;
import net.sourceforge.jpcap.net.UDPPacket;

public class IDSPacketListener implements PacketListener
{
	private UDPRuleProcessor udpProcessor;	
	private TCPRuleProcessor tcpProcessor;
	public IDSPacketListener(List<Rule> rules)
	{
		udpProcessor = new UDPRuleProcessor(rules);
		tcpProcessor = new TCPRuleProcessor(rules);
	}

	@Override
	public void packetArrived(Packet packet) 
	{
		if (packet instanceof UDPPacket)
		{
			udpProcessor.processRules((UDPPacket)packet);
		}
		else if (packet instanceof TCPPacket)
		{
			tcpProcessor.processRules((TCPPacket)packet);
		}
	}

}
