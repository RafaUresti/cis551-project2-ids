import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sourceforge.jpcap.net.UDPPacket;


public class UDPRuleProcessor {
	
	private List<ProtocolRule> udpRules;
	private Map<Rule, Integer> udpMap;
	private String host;
	private int count;
	
	public UDPRuleProcessor(List<Rule> rules)
	{
		udpMap = new HashMap<Rule, Integer>();
		if (rules.size() > 0)
		{
			host = rules.get(0).getHost();
		}
		
		cacheRules(rules);

	}
	
	public void processRules(UDPPacket packet)
	{
		count++;
		boolean isReceive = packet.getDestinationAddress().equals(host);
		for (Rule rule : udpRules) {
			ProtocolRule prule = (ProtocolRule)rule;
			String srcPort = isReceive ? prule.getDstPort() : prule.getSrcPort();
			String dstPort = isReceive ? prule.getSrcPort() : prule.getDstPort();
			if (!srcPort.equals("any") &&
			    packet.getSourcePort() != Integer.parseInt(srcPort)) {
				udpMap.remove(rule);
				continue;
			}
			if (!dstPort.equals("any") &&
				packet.getDestinationPort() != Integer.parseInt(dstPort)) {
				udpMap.remove(rule);
				continue;
			}
			
			if (!prule.getIp().equals("any") &&
				((isReceive && !packet.getSourceAddress().equals(prule.getIp())) ||
				 (!isReceive && !packet.getDestinationAddress().equals(prule.getIp())))) {
				udpMap.remove(rule);
				continue;
			}
			Integer subRule = udpMap.get(rule);
			if (subRule == null) {
				subRule = 0;
			}
			String data = null;
			try
			{data=new String(packet.getData(),"ISO-8859-1");
			}catch(Exception exc){exc.printStackTrace();}
			SubRule srule = prule.getSubRule().get(subRule);
			if ((isReceive && srule.isReceived() && srule.getPattern().matcher(data).find()) ||
				(!isReceive && !srule.isReceived() && srule.getPattern().matcher(data).find())) {
				if (subRule + 1 == prule.getSubRule().size()) {
					System.out.println("Rule: " +rule.getName()+" UDP Packet # "+count);
					udpMap.remove(rule);
				}
				else {
					udpMap.put(rule, subRule+1);
				}
			}
			else {
				udpMap.remove(rule);
			}
		}
	}
	
	private void cacheRules(List<Rule> rules) {
		udpRules = new ArrayList<ProtocolRule>();
		for (Rule rule : rules) {
			if (rule instanceof ProtocolRule) {
				ProtocolRule pr = (ProtocolRule)rule;
				if (pr.getProtocol().equals("udp")) {
					udpRules.add(pr);
				}
			}
		}
	}
}
