import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sourceforge.jpcap.net.TCPPacket;
import net.sourceforge.jpcap.util.ArrayHelper;


public class Conversation 
{
	private String host;
	
	private List<TCPPacket> packets;
	
	private Map<Long, TCPPacket> sendWaiting;
	private Map<Long, TCPPacket> recvWaiting;
	private byte[] sendData = new byte[0];
	private byte[] recvData = new byte[0];
	private long sendSequence = -1;
	private long recvSequence = -1;
	private boolean finished;
	private long count = 0;
	private List<Rule> violatedRules;
	public Conversation(String host)
	{
		violatedRules = new ArrayList<Rule>();
		sendWaiting = new HashMap<Long, TCPPacket>();
		recvWaiting = new HashMap<Long, TCPPacket>();
		packets = new ArrayList<TCPPacket>();
		this.host = host;
	}
	
	public void addPacket(TCPPacket packet)
	{
		count++;
		if (packet.isFin()||packet.isRst()) {
			System.out.println("Finished");
			this.finished = true; 
		}
		
		boolean isReceived = isReceived(packet);
		
		// If this is an ack, remove the sent packet from our hashtable.
		if (!isReceived && packet.isAck() && packet.getData() == null) {
			sendWaiting.remove(packet.getAcknowledgementNumber());
			sendSequence = packet.getSequenceNumber()+packet.getData().length;
		}
		else if (isReceived && packet.isAck() && packet.getData() == null)
		{
			recvSequence = packet.getSequenceNumber()+packet.getData().length;
		}
		// Otherwise add to the receive list
		else if (isReceived)
		{
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
		else if (!sendWaiting.containsValue(packet.getSequenceNumber())){
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
			// Keep the history of packets
			sendWaiting.put(packet.getSequenceNumber(), packet);
		}
	}
	
	private long addAdditional(TCPPacket packet, long sequence, Map<Long, TCPPacket> waiting)
	{
		packets.add(packet);
		if (isReceived(packet))
			recvData = ArrayHelper.join(recvData, packet.getData());
		else
			sendData = ArrayHelper.join(recvData, packet.getData());
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
	
	public boolean isReceived(TCPPacket packet)
	{
		return packet.getDestinationAddress().equals(host);
	}

	public boolean isFinished() {
		return finished;
	}

	public List<TCPPacket> getPackets() {
		return packets;
	}

	public void setPackets(List<TCPPacket> packets) {
		this.packets = packets;
	}

	public byte[] getSendData() {
		return sendData;
	}

	public void setSendData(byte[] sendData) {
		this.sendData = sendData;
	}

	public byte[] getRecvData() {
		return recvData;
	}

	public void setRecvData(byte[] recvData) {
		this.recvData = recvData;
	}

	public long getCount() {
		return count;
	}

	public void setCount(long count) {
		this.count = count;
	}
	public void addRule(Rule rule)
	{
		violatedRules.add(rule);
	}
	public boolean containsRule(Rule rule)
	{
		return violatedRules.contains(rule);
	}
}
