import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sourceforge.jpcap.net.TCPPacket;
public class TCPRuleProcessor
{
	private List<ProtocolRule> protocolRules;
	private List<StreamRule> streamRules;
	private Map<String, Conversation> tcpMap;
	private String host;
	private int count = 0;
	
	public TCPRuleProcessor(List<Rule> rules)
	{
		tcpMap = new HashMap<String, Conversation>();
		
		// Get the host.  It will be used to determine
		// whether the data was sent or received.
		if (rules.size() > 0)
		{
			host = rules.get(0).getHost();
		}
		
		cacheRules(rules);
	}
	
	/**
	 * Compare the rules to the provided packets.
	 * 
	 * @param packet TCP Packet to check.
	 */
	public void processRules(TCPPacket packet)
	{
		count++;
		
		// Values are set based on where the data came from.
		boolean isReceive = packet.getDestinationAddress().equals(host);
		String address = isReceive ? packet.getSourceAddress() :packet.getDestinationAddress();
		int dstPort = isReceive ? packet.getDestinationPort() : packet.getSourcePort();
		int srcPort = isReceive ? packet.getSourcePort() :packet.getDestinationPort();
		
		//We generate a key which will identify the stream
		String key = address + ":" +
				dstPort + ":" +
				srcPort;
		
		// If the stream does not exist, create it now.
		Conversation conversation = tcpMap.get(key);
		if (conversation == null) {
			conversation = new Conversation(host);
			tcpMap.put(key, conversation);
		}
		conversation.addPacket(packet);
		
		// Run the rules.
		try {
			matchStreamRules(conversation);
			matchProtocolRules(conversation);
		}
		catch (Exception exc) {
			exc.printStackTrace();
		}
		
		// If the stream is finished, remove from the map.
		if (conversation.isFinished()) {
			tcpMap.remove(key);
		}
	}	
	

	public void matchProtocolRules(Conversation stream) throws Exception {
		List<TCPPacket> packets = stream.getPackets();
		for (int pindex=0;pindex<packets.size();pindex++) {
			for (ProtocolRule rule : protocolRules) {
				if (!stream.containsRule(rule) && basicCheck(rule, packets.get(0))) {
					int skipCount = 0;
					for (int subIndex=0;subIndex<rule.getSubRule().size();subIndex++) {
						if (pindex+subIndex+skipCount < packets.size()/* && !isSkippable(packets.get(pindex+subIndex+skipCount))*/) {
							TCPPacket packet = packets.get(pindex+subIndex+skipCount);
							boolean isReceive = isReceived(packet);
							String data=new String(packet.getData(),"ISO-8859-1");
							
							SubRule srule = rule.getSubRule().get(subIndex);
							if (flagsMatch(packet,srule) &&
									(isReceive && srule.isReceived() && srule.getPattern().matcher(data).find()) ||
									(!isReceive && !srule.isReceived() && srule.getPattern().matcher(data).find())) {
								if (subIndex + 1 == rule.getSubRule().size()) {
									flagRule(rule, stream);
								}
							}
							else {
								//System.out.println("Rule: "+rule.getName());
								//System.out.println(j+" "+isReceive+" " + srule.isReceived() + " " + srule.getPattern().matcher(data).find() + " " + flagsMatch(packet, srule)+" "+data+" "+srule.getPattern().pattern());
								break;
							}
						}
						else if (pindex+subIndex+skipCount < packets.size()/* && isSkippable(packets.get(pindex+subIndex+skipCount))*/)
						{
							subIndex--;
							skipCount++;
						}
							//System.out.println(i+j+skipCount);
					}
				}
			}
		}
	}
	
	private void matchStreamRules(Conversation c) throws Exception
	{
		for (StreamRule rule : streamRules)
		{
			if (!c.containsRule(rule) && basicCheck(rule, c.getPackets().get(0)))
			{
				if (rule.isReceive() && c.getRecvData() != null) {
					String rec = new String (c.getRecvData(), "ISO-8859-1");
					if (rule.getPattern().matcher(rec).find()) {
						flagRule(rule, c);
					}
				}
				
				//Regular expression over what is sent
				else if (!rule.isReceive() && c.getSendData() != null) {
					String sen = new String (c.getSendData(), "ISO-8859-1");	
					if (rule.getPattern().matcher(sen).find()) {
						flagRule(rule, c);
					}
				}
			}
		}
	}
	
	private void flagRule(Rule rule, Conversation stream)
	{
		System.out.println("Rule: " +rule.getName()+ " TCP Packet # "+count);
		stream.addRule(rule);
	}
	
	/**
	 * 
	 * 
	 * @param packet
	 * @return
	 */
	/**private boolean isSkippable(TCPPacket packet) {
		boolean result = false;
		if (packet.isAck() && (packet.getData() == null || packet.getData().length==0)) {
			result = true;
		}
		return result;
	}**/
	private boolean flagsMatch(TCPPacket packet, SubRule srule)
	{
		if (srule.getFlags() == null)
		{
			return true;
		}
		int count = 0;
		int count2 = 0;
		if (packet.isAck()) count++;
		if (packet.isFin()) count++;
		if (packet.isPsh()) count++;
		if (packet.isRst()) count++;
		if (packet.isSyn()) count++;
		if (packet.isUrg()) count++;
		for (char flag : srule.getFlags())
		{
			if (flag == IDS.ACK && packet.isAck()) count2++;
			if (flag == IDS.FIN && packet.isFin()) count2++;
			if (flag == IDS.PSH && packet.isPsh()) count2++;
			if (flag == IDS.RST && packet.isRst()) count2++;
			if (flag == IDS.SYN && packet.isSyn()) count2++;
			if (flag == IDS.URG && packet.isUrg()) count2++;
		}
		//System.out.println(count + " " + count2 + " "+ srule.getFlags().size());
		return count == count2;
	}
	private boolean basicCheck(Rule rule, TCPPacket packet)
	{
		boolean isReceive = isReceived(packet);
		String srcPort = isReceive ? rule.getDstPort() : rule.getSrcPort();
		String dstPort = isReceive ? rule.getSrcPort() : rule.getDstPort();
		if (!srcPort.equals("any") &&
		    packet.getSourcePort() != Integer.parseInt(srcPort))
		{
			return false;
		}
		if (!dstPort.equals("any") &&
			packet.getDestinationPort() != Integer.parseInt(dstPort))
		{
			return false;
		}
		
		if (!rule.getIp().equals("any") &&
			((isReceive && !packet.getSourceAddress().equals(rule.getIp())) ||
			 (!isReceive && !packet.getDestinationAddress().equals(rule.getIp()))))
		{
			return false;
		}
		return true;
	}
	public boolean isReceived(TCPPacket packet)
	{
		return packet.getDestinationAddress().equals(host);
	}
	
	private void cacheRules(List<Rule> rules) {
		protocolRules = new ArrayList<ProtocolRule>();
		streamRules = new ArrayList<StreamRule>();
		for (Rule rule : rules) {
			if (rule instanceof ProtocolRule) {
				protocolRules.add((ProtocolRule)rule);
			}
			else streamRules.add((StreamRule)rule);
		}
	}
}
