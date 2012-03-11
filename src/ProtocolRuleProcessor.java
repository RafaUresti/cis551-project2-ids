import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sourceforge.jpcap.net.Packet;
import net.sourceforge.jpcap.net.UDPPacket;
public class ProtocolRuleProcessor
{
	private List<Rule> udpRules;
	private List<Rule> tcpRules;
	private Map<Rule, Integer> udpMap;
	private String host;
	
	public ProtocolRuleProcessor(List<Rule> rules)
	{
		udpMap = new HashMap<Rule, Integer>();
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
				udpMap.remove(rule);
				continue;
			}
			if (!prule.getDstPort().equals("any") &&
				packet.getDestinationPort() != Integer.parseInt(prule.getDstPort()))
			{
				udpMap.remove(rule);
				continue;
			}
			
			if (!prule.getIp().equals("any") &&
				((isReceive && !packet.getSourceAddress().equals(prule.getIp())) ||
				 (!isReceive && !packet.getDestinationAddress().equals(prule.getIp()))))
			{
				udpMap.remove(rule);
				continue;
			}
			Integer subRule = udpMap.get(rule);
			if (subRule == null)
			{
				subRule = 0;
			}
			String data = new String(packet.getData());
			SubRule srule = prule.getSubRule().get(subRule);
			
			if ((isReceive && srule.getRecv()!=null && data.contains(srule.getRecv())) ||
				(!isReceive && srule.getSnd()!=null && data.contains(srule.getSnd())))
			{
				if (subRule + 1 == prule.getSubRule().size())
				{
					udpMap.remove(rule);
					System.out.println("Rule: "+rule.getName());
				}
				else
				{
					udpMap.put(rule, subRule+1);
				}
			}
			else
			{
				udpMap.remove(rule);
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
