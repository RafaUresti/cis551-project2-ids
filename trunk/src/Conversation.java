import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sourceforge.jpcap.net.TCPPacket;


public class Conversation 
{
	
	private String host;
	
	private List<TCPPacket> packets;
	
	private Map<Long, TCPPacket> sendWaiting;
	private Map<Long, TCPPacket> recvWaiting;
	private long sendSequence = -1;
	private long recvSequence = -1;
	private boolean finished;
	int ruleChecked = 0;
	public Conversation(String host)
	{
		sendWaiting = new HashMap<Long, TCPPacket>();
		recvWaiting = new HashMap<Long, TCPPacket>();
		packets = new ArrayList<TCPPacket>();
		this.host = host;
	}
	
	public void addPacket(TCPPacket packet)
	{
		if (packet.isFin()||packet.isRst()) {
			//The communication is over
			this.finished = true; 
		}
		if (isReceived(packet)) {
			if (recvSequence == -1) {
				recvSequence = packet.getSequenceNumber()+1;
				packets.add(packet);
			}
			else if (recvSequence == packet.getSequenceNumber()) {
				addAdditional(packet, recvSequence, recvWaiting);
				recvSequence++;
			}
			else {
				recvWaiting.put(packet.getSequenceNumber(), packet);
			}
		}
		else {
			if (sendSequence == -1) {
				sendSequence = packet.getSequenceNumber()+1;
				packets.add(packet);
			}
			else if (sendSequence == packet.getSequenceNumber()) {
				addAdditional(packet, sendSequence, sendWaiting);
				sendSequence++;
			}
			else {
				sendWaiting.put(packet.getSequenceNumber(), packet);
			}
		}
	}
	
	private void addAdditional(TCPPacket packet, long sequence, Map<Long, TCPPacket> waiting)
	{
		packets.add(packet);
		TCPPacket p = null;
		do {
			p = waiting.get(++sequence);
			if (p != null) {
				packets.add(p);
				waiting.remove(sequence);
			}
		} while (p != null);
	}
	
	public void matchesRules(List<Rule> rules) {
		for (int i=ruleChecked;i<packets.size();i++) {
			for (Rule rule : rules) {
				if (basicCheck(rule, packets.get(0))) {
					for (int j=0;j<rule.getPrule().getSubRule().size();j++) {
						if (i+j < packets.size() && !isSkippable(packets.get(i+j))) {
							TCPPacket packet = packets.get(i+j);
							boolean isReceive = isReceived(packet);
							String data = null;
							try
							{data=new String(packet.getData(),"ISO-8859-1");
							}catch(Exception exc){exc.printStackTrace();}
							SubRule srule = rule.getPrule().getSubRule().get(j);
							if (flagsMatch(packet,srule) &&
									(isReceive && srule.isReceived() && srule.getPattern().matcher(data).find()) ||
									(!isReceive && !srule.isReceived() && srule.getPattern().matcher(data).find())) {
								if (j + 1 == rule.getPrule().getSubRule().size()) {
									System.out.println("I got here");
								}
							}
							else {
								break;
							}
						}
					}
				}
			}
		}
	}
	private boolean isSkippable(TCPPacket packet) {
		boolean result = false;
		if (packet.isAck() && (packet.getData() == null || packet.getData().length==0)) {
			result = true;
		}
		return result;
	}
	private boolean flagsMatch(TCPPacket packet, SubRule srule)
	{
		int count = 0;
		int count2 = 0;
		if (packet.isAck()) count++;
		if (packet.isFin()) count++;
		if (packet.isPsh()) count++;
		if (packet.isRst()) count++;
		if (packet.isSyn()) count++;
		if (packet.isUrg()) count++;
		for (String flag : srule.getFlags())
		{
			if (flag.equalsIgnoreCase("A") && packet.isAck()) count2++;
			if (flag.equalsIgnoreCase("F") && packet.isFin()) count2++;
			if (flag.equalsIgnoreCase("P") && packet.isPsh()) count2++;
			if (flag.equalsIgnoreCase("R") && packet.isRst()) count2++;
			if (flag.equalsIgnoreCase("S") && packet.isSyn()) count2++;
			if (flag.equalsIgnoreCase("U") && packet.isUrg()) count2++;
		}
		return count == count2;
	}
	private boolean basicCheck(Rule rule, TCPPacket packet)
	{
		boolean isReceive = isReceived(packet);
		ProtocolRule prule = rule.getPrule();
		String srcPort = isReceive ? prule.getDstPort() : prule.getSrcPort();
		String dstPort = isReceive ? prule.getSrcPort() : prule.getDstPort();
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
		
		if (!rule.getPrule().getIp().equals("any") &&
			((isReceive && !packet.getSourceAddress().equals(prule.getIp())) ||
			 (!isReceive && !packet.getDestinationAddress().equals(prule.getIp()))))
		{
			return false;
		}
		return true;
	}
	private boolean isReceived(TCPPacket packet)
	{
		return packet.getDestinationAddress().equals(host);
	}

	public boolean isFinished() {
		return finished;
	}
}