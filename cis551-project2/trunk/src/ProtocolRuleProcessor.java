import java.util.List;

import net.sourceforge.jpcap.net.Packet;
public class ProtocolRuleProcessor
{
	private List<Rule> rules;

	public ProtocolRuleProcessor(List<Rule> rules)
	{
		this.rules = rules;

	}

	public void processRules(Packet packet)
	{
		System.out.println("Protocol Processing: "+
							packet.toColoredString(true));
	}
}
