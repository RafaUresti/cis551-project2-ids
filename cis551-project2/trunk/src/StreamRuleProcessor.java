import java.util.List;

import net.sourceforge.jpcap.net.TCPPacket;
public class StreamRuleProcessor
{
	private List<Rule> rules;

	public StreamRuleProcessor(List<Rule> rules)
	{
		this.rules = rules;

	}

	public void processRules(TCPPacket packet)
	{
		System.out.println("Stream Processing: "+
				packet.toColoredString(true));
	}
}
