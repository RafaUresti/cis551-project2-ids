import java.util.ArrayList;
import java.util.List;

import net.sourceforge.jpcap.net.Packet;
import net.sourceforge.jpcap.net.UDPPacket;
public class ProtocolRuleProcessor
{
	private List<Rule> udpRules;
	private List<Rule> tcpRules;
	private String host;
	
	public ProtocolRuleProcessor(List<Rule> rules)
	{
		if (rules.size() > 0)
		{
			host = rules.get(0).getHost();
		}
		
		cacheRules(rules);

	}

	
	public void processRules(Packet packet)
	{
		if (packet instanceof UDPPacket)
		{
			processUDP((UDPPacket)packet);
		}
		
	}
	
	private void processUDP(UDPPacket packet)
	{
		boolean isReceive = packet.getDestinationAddress().equals(host);
		
		for (Rule rule : udpRules)
		{
			ProtocolRule prule = rule.getPrule();
			if (!prule.getSrcPort().equals("any") &&
			    packet.getSourcePort() != Integer.parseInt(rule.getPrule().getSrcPort()))
			{
				continue;
			}
			if (!prule.getDstPort().equals("any") &&
				packet.getDestinationPort() != Integer.parseInt(prule.getDstPort()))
			{
				continue;
			}
			
			if (!prule.getIp().equals("any") &&
				((isReceive && !packet.getSourceAddress().equals(prule.getIp())) ||
				 (!isReceive && !packet.getDestinationAddress().equals(prule.getIp()))))
			{
				continue;
			}
			
			String data = new String(packet.getData());
			for (SubRule srule : prule.getSubRule())
			{
				if ((isReceive && data.contains(srule.getRecv())) ||
					(!isReceive && data.contains(srule.getSnd())))
				{
					System.out.println("Rule: "+rule.getName());
				}
			}
		}
	}
	
	private void cacheRules(List<Rule> rules)
	{
		udpRules = new ArrayList<Rule>();
		tcpRules = new ArrayList<Rule>();
		for (Rule rule : rules)
		{
			if (rule.getPrule() != null)
			{
				ProtocolRule pr = rule.getPrule();
				if (pr.getProtocol().equals("udp"))
				{
					udpRules.add(rule);
				}
				else
				{
					tcpRules.add(rule);
				}
			}
		}
	}
}
