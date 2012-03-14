import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sourceforge.jpcap.net.TCPPacket;
import net.sourceforge.jpcap.util.ArrayHelper;

/**
 * Class that represents a TCP session.  It keeps track
 * of a stream of data, as well as individual packets for
 * protocol rules.
 *
 */
public class TCPSession 
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
	private List<Rule> violatedRules;
	private Map<Rule, List <Integer>> inProgress;
	public TCPSession(String host)
	{
		inProgress = new HashMap<Rule, List<Integer>>();
		violatedRules = new ArrayList<Rule>();
		sendWaiting = new HashMap<Long, TCPPacket>();
		recvWaiting = new HashMap<Long, TCPPacket>();
		packets = new ArrayList<TCPPacket>();
		this.host = host;
	}
	
	public void addPacket(TCPPacket packet)
	{
		if (packet.isFin()||packet.isRst()) {
			this.finished = true; 
		}
		
		boolean isReceived = isReceived(packet);
		
		// If this is an ack, remove the sent packet from our hashtable.
		if (!isReceived && packet.isAck() && packet.getData() == null) {
			// remove an acknowledged packet from the send map.
			sendWaiting.remove(packet.getAcknowledgementNumber());
			sendSequence = packet.getSequenceNumber()+packet.getData().length;
		}
		else if (isReceived && packet.isAck() && packet.getData() == null)
		{
			recvSequence = packet.getSequenceNumber()+packet.getData().length;
		}
		// Otherwise add to the receive list.
		else if (isReceived)
		{
			if (recvSequence == -1) {
				recvSequence = packet.getSequenceNumber()+packet.getData().length;
				if (packet.getData().length == 0) recvSequence++;
				packets.add(packet);
			}
			else if (recvSequence == packet.getSequenceNumber()) {
				recvSequence = addAdditional(packet, recvSequence, recvWaiting);
			}
			else {
				// This was received out of order, add to the map and wait
				// for the packet to come in order.
				recvWaiting.put(packet.getSequenceNumber(), packet);
			}
		}
		// If this is a send, and to the send list.
		else if (!sendWaiting.containsValue(packet.getSequenceNumber())){
			if (sendSequence == -1) {
				sendSequence = packet.getSequenceNumber()+packet.getData().length;
				if (packet.getData().length == 0) sendSequence++;
				packets.add(packet);
			}
			else if (sendSequence == packet.getSequenceNumber()) {
				sendSequence = addAdditional(packet, sendSequence, sendWaiting);
			}
			// Keep the history of packets, that way we don't add it twice if
			// it needs to be resent.
			sendWaiting.put(packet.getSequenceNumber(), packet);
		}
	}
	
	/**
	 * Adds the received packets as well as any additional packets that were
	 * received out of order.
	 * 
	 * @param packet
	 * @param sequence
	 * @param waiting
	 * @return
	 */
	private long addAdditional(TCPPacket packet, long sequence, Map<Long, TCPPacket> waiting)
	{
		// Add the current packet.
		packets.add(packet);
		if (isReceived(packet))
			recvData = ArrayHelper.join(recvData, packet.getData());
		else
			sendData = ArrayHelper.join(recvData, packet.getData());
		sequence +=packet.getData().length;
		TCPPacket p = null;
		
		// Add any additional packets that may have been received out of order.
		do {
			p = waiting.get(sequence);
			if (p != null) {
				packets.add(p);
				waiting.remove(sequence);
				sequence+=packet.getData().length;
				if (isReceived(packet))
					recvData = ArrayHelper.join(recvData, packet.getData());
				else
					sendData = ArrayHelper.join(recvData, packet.getData());
			}
		} while (p != null);
		return sequence;
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
	 * Determines if the connection is finished.
	 * 
	 * @return
	 */
	public boolean isFinished() {
		return finished;
	}

	/**
	 * Get the packets in conversation order.
	 */
	public List<TCPPacket> getPackets() {
		return packets;
	}

	/**
	 * Get the sent data.
	 */
	public byte[] getSendData() {
		return sendData;
	}

	/**
	 * Get the received data.
	 */
	public byte[] getRecvData() {
		return recvData;
	}
	/**
	 * Add a rule to the list of violated rules in this session.
	 * 
	 * @param rule
	 */
	public void addRule(Rule rule)
	{
		violatedRules.add(rule);
	}
	public boolean containsRule(Rule rule)
	{
		return violatedRules.contains(rule);
	}

	public Map<Rule, List<Integer>> getInProgress() {
		return inProgress;
	}
}
