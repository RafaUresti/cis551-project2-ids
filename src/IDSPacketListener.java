import java.util.List;

import net.sourceforge.jpcap.capture.PacketListener;
import net.sourceforge.jpcap.net.Packet;
import net.sourceforge.jpcap.net.TCPPacket;

public class IDSPacketListener implements PacketListener
{
	private StreamRuleProcessor streamProcessor;	
	private ProtocolRuleProcessor protocolProcessor;
	public IDSPacketListener(List<Rule> rules)
	{
		streamProcessor = new StreamRuleProcessor(rules);
		protocolProcessor = new ProtocolRuleProcessor(rules);
	}

	@Override
	public void packetArrived(Packet packet) 
	{
		if (packet instanceof TCPPacket)
		{
			streamProcessor.processRules((TCPPacket)packet);
		}
	
		protocolProcessor.processRules(packet);
	}

}
