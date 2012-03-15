import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sourceforge.jpcap.net.UDPPacket;

/**
 * Class respsonible for matching TCP packets to TCP rules.
 * 
 * @author bbreck
 *
 */
public class UDPRuleProcessor {
	
	// The list of UDP rules.
	private List<ProtocolRule> udpRules;
	
	// Map that keeps track of rules in progress
	private Map<String, UDPSession> udpMap;
	private String host;
	private int count;
	
	/**
	 * Constructor that accepts a list of rules.
	 * 
	 * @param rules
	 */
	public UDPRuleProcessor(List<Rule> rules)
	{
		udpMap = new HashMap<String, UDPSession>();
		if (rules.size() > 0)
		{
			host = rules.get(0).getHost();
		}	
		cacheRules(rules);

	}
	
	/**
	 * Process a UDP Packet.
	 * 
	 * @param packet
	 */
	public void processRules(UDPPacket packet)
	{
		count++;
		
		// Values are set based on where the data came from.
		boolean isReceive = packet.getDestinationAddress().equals(host);
		String address = isReceive ? packet.getSourceAddress() :
								packet.getDestinationAddress();
		int dstPort = isReceive ? packet.getDestinationPort() : 
								packet.getSourcePort();
		int srcPort = isReceive ? packet.getSourcePort() :
								packet.getDestinationPort();
		
		//We generate a key which will identify the stream
		String key = address + ":" +
				dstPort + ":" +
				srcPort;
		
		for (Rule rule : udpRules) {
			
			// Compare against the basic rules
			ProtocolRule prule = (ProtocolRule)rule;
			int sPort = isReceive ? packet.getDestinationPort() : packet.getSourcePort();
			int dPort = isReceive ? packet.getSourcePort() : packet.getDestinationPort();
			if (!rule.getSrcPort().equals("any") &&
			    sPort != Integer.parseInt(rule.getSrcPort())) {
				continue;
			}
			if (!rule.getDstPort().equals("any") &&
				dPort != Integer.parseInt(rule.getDstPort())) {
				continue;
			}
			
			if (!prule.getIp().equals("any") &&
				((isReceive && !packet.getSourceAddress().equals(prule.getIp())) ||
				 (!isReceive && !packet.getDestinationAddress().equals(prule.getIp())))) {
				continue;
			}
			// If the basic rules pass, take a look at the sub rules. If a rule
			// repeats values multiple times, there may be multiple rule checks
			// occurring at once, only at diferent stages. Check all of them now.
			List<Integer> subRuleList = getRuleProgress(key, rule);
			List<Integer> newRuleList = new ArrayList<Integer>();
			while (subRuleList.size()>0)
			{
				Integer subRule = subRuleList.remove(0);
				// Always remove because you are doing the check now.
				// If it is part of a rule then the next subrule will
				// be added to the list later if necessary.
				subRuleList.remove(subRule);
				
				String data = null;
				try
				{
					data=new String(packet.getData(),"ISO-8859-1");
				}
				catch(Exception exc){exc.printStackTrace();}
				
				// If the subrule matches, either print the rule match
				// text because we are at the end of the sub-rules, or 
				// add the next subRule to the list so that it
				// can be checked against the next packet.
				SubRule srule = prule.getSubRule().get(subRule);
				if ((isReceive && srule.isReceived() && 
						srule.getPattern().matcher(data).find()) ||
					(!isReceive && !srule.isReceived() && 
						srule.getPattern().matcher(data).find())) {
					if (subRule + 1 == prule.getSubRule().size()) {
						System.out.println("Rule: " +rule.getName()+
											" UDP Packet # "+count);
					}
					else {
						newRuleList.add(subRule+1);
					}
				}	
			}
			udpMap.get(key).getUdpMap().put(rule, newRuleList);
		}
	}
	/**
	 * Get the index of the sub rules to check for the next UDP
	 * packet.
	 * 
	 * @param key
	 * @param rule
	 * @return
	 */
	private List<Integer> getRuleProgress(String key, Rule rule)
	{
		UDPSession session = udpMap.get(key);
		if (session == null)
		{
			session = new UDPSession();
			udpMap.put(key, session);
		}
		
		List<Integer> subRuleList = session.getUdpMap().get(rule);
		if (subRuleList == null) {
			subRuleList = new ArrayList<Integer>();
			session.getUdpMap().put(rule, subRuleList);
		}
		// Always add the first sub-rule.
		subRuleList.add(0);
		return subRuleList;
	}
	
	/**
	 * Saves the rules by type so that non-applicable rules are not
	 * checked.
	 * 
	 * @param rules
	 */
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
