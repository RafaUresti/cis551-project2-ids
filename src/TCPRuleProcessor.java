import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sourceforge.jpcap.net.TCPPacket;

/**
 * Class respsonible for matching TCP packets to TCP rules.
 * 
 * @author bbreck
 *
 */
public class TCPRuleProcessor
{
	// Protocol rules.
	private List<ProtocolRule> protocolRules;
	
	// Stream rules.
	private List<StreamRule> streamRules;
	
	// Current TCP connections being tracked.
	private Map<String, TCPSession> tcpMap;
	
	// The current host.
	private String host;
	
	// Number of TCP packets seen so far.
	private int count = 0;
	
	/**
	 * Constructor that accepts a list of rules.
	 * 
	 * @param rules
	 */
	public TCPRuleProcessor(List<Rule> rules)
	{
		tcpMap = new HashMap<String, TCPSession>();
		
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
		TCPSession conversation = tcpMap.get(key);
		if (conversation == null) {
			conversation = new TCPSession(host);
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
	
	/**
	 * Compare the stream to the protocol rules.
	 * 
	 * @param stream
	 * @throws Exception
	 */
	private void matchProtocolRules(TCPSession stream) throws Exception {
		List<TCPPacket> packets = stream.getPackets();
		
		for (int pindex=0;pindex<packets.size();pindex++) {
			boolean keepPacket = false;
			for (ProtocolRule rule : protocolRules) {
				if (!stream.containsRule(rule) && basicCheck(rule, packets.get(0))) {
					// number of packets (i.e. ACKs) that have been ignored
					int skipCount = 0;
					for (int subIndex=0;subIndex<rule.getSubRule().size();subIndex++) {
						if (pindex+subIndex+skipCount < packets.size() && 
							!isSkippable(packets.get(pindex+subIndex+skipCount))) {
							
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
								if (pindex == packets.size()-1)
								{
									keepPacket = true;
								}
							}
							else {
								//System.out.println("Rule: "+rule.getName());
								//System.out.println(j+" "+isReceive+" " + srule.isReceived() + " " + srule.getPattern().matcher(data).find() + " " + flagsMatch(packet, srule)+" "+data+" "+srule.getPattern().pattern());
								break;
							}
						}
						else if (pindex+subIndex+skipCount < packets.size() && isSkippable(packets.get(pindex+subIndex+skipCount)))
						{
							subIndex--;
							skipCount++;
						}
							//System.out.println(i+j+skipCount);
					}
				}
			}
			if (!keepPacket)
			{
				packets.remove(0);
				pindex--;
			}
		}
	}
	
	/**
	 * Method that determines whether the packet can be skipped in a
	 * protocol comparison. This is true when the packet is an ACK and
	 * has no body.
	 * 
	 * @param packet
	 * @return
	 */
	private boolean isSkippable(TCPPacket packet) {
		boolean result = false;
		if (packet.isAck() && (packet.getData() == null || 
				packet.getData().length==0)) {
			result = true;
		}
		return result;
	}
	
	private void matchStreamRules(TCPSession c) throws Exception
	{
		// If there are no packets, stop here.
		if (c.getPackets().size() == 0)
			return;
		
		// Iterate over the rules.
		for (StreamRule rule : streamRules)
		{
			if (!c.containsRule(rule) && basicCheck(rule, c.getPackets().get(0)))
			{
				// If it is a receive rule, compare against the receive data.
				if (rule.isReceive() && c.getRecvData() != null) {
					String rec = new String (c.getRecvData(), "ISO-8859-1");
					if (rule.getPattern().matcher(rec).find()) {
						flagRule(rule, c);
					}
				}
				
				// If it is a send rule, compare against the send data.
				else if (!rule.isReceive() && c.getSendData() != null) {
					String sen = new String (c.getSendData(), "ISO-8859-1");	
					if (rule.getPattern().matcher(sen).find()) {
						flagRule(rule, c);
					}
				}
			}
		}
	}
	
	/**
     * Compares all common aspects of rules to the packet (i.e. Source
     * Port, Destination Port, Other IP Address).
     * 
     * @param rule
     * @param packet
     * @return
     */
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
    
    /**
	 * Determines if the host was the receiver of the packet.
	 * 
	 * @param packet
	 * @return
	 */
	private boolean isReceived(TCPPacket packet)
	{
		return packet.getDestinationAddress().equals(host);
	}
	
	/**
	 * Print the fact that a rule was found, and add the rule to the stream.
	 * 
	 * @param rule
	 * @param stream
	 */
	private void flagRule(Rule rule, TCPSession stream)
	{
		System.out.println("Rule: " +rule.getName()+ " TCP Packet # "+count);
		stream.addRule(rule);
	}
	
	/**
	 * Determines whether the number and type of flags match
	 * between a packet and a rule.
	 * 
	 * @param packet
	 * @param srule
	 * @return
	 */
	private boolean flagsMatch(TCPPacket packet, SubRule srule)
	{
		// If flags is null, we do not care.
		if (srule.getFlags() == null)
		{
			return true;
		}
		int packetCount = 0;
		int ruleCount = 0;
		// Get the packet count.
		if (packet.isAck()) packetCount++;
		if (packet.isFin()) packetCount++;
		if (packet.isPsh()) packetCount++;
		if (packet.isRst()) packetCount++;
		if (packet.isSyn()) packetCount++;
		if (packet.isUrg()) packetCount++;
		
		// Get the rule/packet count.
		for (char flag : srule.getFlags())
		{
			if (flag == IDS.ACK && packet.isAck()) ruleCount++;
			if (flag == IDS.FIN && packet.isFin()) ruleCount++;
			if (flag == IDS.PSH && packet.isPsh()) ruleCount++;
			if (flag == IDS.RST && packet.isRst()) ruleCount++;
			if (flag == IDS.SYN && packet.isSyn()) ruleCount++;
			if (flag == IDS.URG && packet.isUrg()) ruleCount++;
		}
		
		// Compare counts and return the result.
		return packetCount == ruleCount;
	}
	
	/**
	 * Saves the rules by type so that non-applicable rules are not
	 * checked.
	 * 
	 * @param rules
	 */
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
