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
			System.out.println("Finished");
			this.finished = true; 
		}
		if (isReceived(packet)) {
			if (recvSequence == -1) {
				recvSequence = packet.getSequenceNumber()+packet.getData().length;
				//System.out.println("recv "+recvSequence+" first " +new String(packet.getData()));
				if (packet.getData().length == 0) recvSequence++;
				packets.add(packet);
			}
			else if (recvSequence == packet.getSequenceNumber()) {
				recvSequence = addAdditional(packet, recvSequence, recvWaiting);
				//System.out.println("recv "+recvSequence+" added"+new String(packet.getData()));
			}
			else {
				recvWaiting.put(packet.getSequenceNumber(), packet);
				//System.out.println("recv "+recvSequence+" waiting"+new String(packet.getData()));
			}
		}
		else {
			if (sendSequence == -1) {
				sendSequence = packet.getSequenceNumber()+packet.getData().length;
				//System.out.println("send "+recvSequence+" first " +new String(packet.getData()));
				if (packet.getData().length == 0) sendSequence++;
				packets.add(packet);
			}
			else if (sendSequence == packet.getSequenceNumber()) {
				sendSequence = addAdditional(packet, sendSequence, sendWaiting);
				//System.out.println("send "+recvSequence+" added"+new String(packet.getData()));
			}
			else {
				sendWaiting.put(packet.getSequenceNumber(), packet);
				//System.out.println("send "+recvSequence+" waiting"+new String(packet.getData()));
			}
		}
	}
	
	private long addAdditional(TCPPacket packet, long sequence, Map<Long, TCPPacket> waiting)
	{
		packets.add(packet);
		sequence +=packet.getData().length;
		TCPPacket p = null;
		do {
			p = waiting.get(sequence);
			if (p != null) {
				packets.add(p);
				waiting.remove(sequence);
				sequence+=packet.getData().length;
			}
		} while (p != null);
		return sequence;
	}
	
	public void matchesRules(List<Rule> rules) {
		for (int i=0;i<packets.size();i++) {
			for (Rule rule : rules) {
				if (basicCheck(rule, packets.get(0))) {
						int skipCount = 0;
					for (int j=0;j<rule.getPrule().getSubRule().size();j++) {
						if (i+j+skipCount < packets.size() && !isSkippable(packets.get(i+j+skipCount))) {
							TCPPacket packet = packets.get(i+j+skipCount);
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
									System.out.println("Rule: " +rule.getName());
								}
							}
							else {
								//System.out.println("Rule: "+rule.getName());
								//System.out.println(j+" "+isReceive+" " + srule.isReceived() + " " + srule.getPattern().matcher(data).find() + " " + flagsMatch(packet, srule)+" "+data+" "+srule.getPattern().pattern());
								break;
							}
						}
						else if (i+j+skipCount < packets.size() && isSkippable(packets.get(i+j+skipCount)))
						{
							j--;
							skipCount++;
						}
							//System.out.println(i+j+skipCount);
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
		for (String flag : srule.getFlags())
		{
			if (flag.equalsIgnoreCase("ack") && packet.isAck()) count2++;
			if (flag.equalsIgnoreCase("fin") && packet.isFin()) count2++;
			if (flag.equalsIgnoreCase("psh") && packet.isPsh()) count2++;
			if (flag.equalsIgnoreCase("rst") && packet.isRst()) count2++;
			if (flag.equalsIgnoreCase("syn") && packet.isSyn()) count2++;
			if (flag.equalsIgnoreCase("urg") && packet.isUrg()) count2++;
		}
		//System.out.println(count + " " + count2 + " "+ srule.getFlags().size());
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
