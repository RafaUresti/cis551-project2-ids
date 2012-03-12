import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sourceforge.jpcap.net.Packet;
import net.sourceforge.jpcap.net.TCPPacket;
import net.sourceforge.jpcap.net.UDPPacket;
public class ProtocolRuleProcessor
{
	private List<Rule> udpRules;
	private List<Rule> tcpRules;
	private Map<Rule, Integer> udpMap;
	private Map<String, Conversation> tcpMap;
	private String host;
	
	public ProtocolRuleProcessor(List<Rule> rules)
	{
		udpMap = new HashMap<Rule, Integer>();
		tcpMap = new HashMap<String, Conversation>();
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
		else if (packet instanceof TCPPacket)
		{
			try{
			processTCP((TCPPacket)packet);
			}catch(Exception exc) {System.out.println();}
		}
	}

	private void processTCP(TCPPacket packet) throws Exception {
		boolean isReceive = packet.getDestinationAddress().equals(host);
		String address = isReceive ? packet.getSourceAddress() :packet.getDestinationAddress();
		int dstPort = isReceive ? packet.getDestinationPort() : packet.getSourcePort();
		int srcPort = isReceive ? packet.getSourcePort() :packet.getDestinationPort();
		
		//We generate a key which will identify the stream
		String key = address + ":" +
				dstPort + ":" +
				srcPort;
		
		Conversation conversation = tcpMap.get(key);
		if (conversation == null) {
			conversation = new Conversation(host);
			tcpMap.put(key, conversation);
		}
		else {
			conversation.addPacket(packet);
		}
		
		conversation.matchesRules(tcpRules);
		
		if (conversation.isFinished()) {
			//If the connection is over, we print the stream
			System.out.println("*****Stream over*****");
			System.out.println(conversation.toString());
			tcpMap.remove(key);
		}
	}	
	private void processUDP(UDPPacket packet)
	{
		boolean isReceive = packet.getDestinationAddress().equals(host);
		for (Rule rule : udpRules) {
			ProtocolRule prule = rule.getPrule();
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
		udpRules = new ArrayList<Rule>();
		tcpRules = new ArrayList<Rule>();
		for (Rule rule : rules) {
			if (rule.getPrule() != null) {
				ProtocolRule pr = rule.getPrule();
				if (pr.getProtocol().equals("udp")) {
					udpRules.add(rule);
				}
				else {
					tcpRules.add(rule);
				}
			}
		}
	}
}
