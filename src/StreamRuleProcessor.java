import java.util.ArrayList;
import java.util.List;
import net.sourceforge.jpcap.net.TCPPacket;
import java.util.Hashtable;

public class StreamRuleProcessor
{
	private List<Rule> rules;
	private Hashtable<String, ArrayList<TCPPacket>> connections = new Hashtable<String, ArrayList<TCPPacket>>();
	private Hashtable<String, Stream> streams = new Hashtable<String, Stream>();
	private String host = "192.168.0.1";
	
	public StreamRuleProcessor(List<Rule> rules)
	{
		this.rules = rules;
	}
	
	public void processRules(TCPPacket packet)
	{
		System.out.println("Stream Processing: "+
				packet.toColoredVerboseString(true));
		
		if (packet.getDestinationAddress().equals(host))
		{//This packet has been received by the host
			String key = packet.getSourceAddress() + ":" +
					packet.getDestinationPort() + ":" +
					packet.getSourcePort();
			if (connections.containsKey(key)) { 
				//There is a stream that corresponds to this packet
				
				//We add the packet to the corresponding list of packets
				connections.get(key).add(packet);
				
				//We add the packet to the new stream
				streams.get(key).addPacket(packet, "recv");
				
				//We check if the stream follow the rules
				//here here
				
				if (streams.get(key).isFinIsSet()) {
					//If the connection is over, we print the stream
					System.out.println(streams.get(key).toString());
					//And we remove the connection from the hashtables
					connections.remove(key);
					streams.remove(key);
				}
			}
			else {
				//If this is the first time this packet is seen
					//It must be that the connection is establishing	
					
					//We create a new list of TCPPackets, and we add it to the hashtable
					ArrayList<TCPPacket> connection = new ArrayList<TCPPacket>();
					connection.add(packet);
					connections.put(key, connection);
					
					//we create a new stream from this packet, we add it to the hashtable
					Stream stream = new Stream(packet, "recv");
					streams.put(key,stream);
					
					//We Check if the stream follow the rules
					//here here						
			}
		}
		else {//This packet has been sent by the host
			String key = packet.getDestinationAddress() + ":" +
					packet.getDestinationPort() + ":" +
					packet.getSourcePort();
			if (connections.containsKey(key)) { 
				//There is a stream that corresponds to this packet
				
				//We add the packet to the corresponding list of packets
				connections.get(key).add(packet);
				
				//We add the packet to the new stream
				streams.get(key).addPacket(packet, "send");
				
				//We check if the stream follow the rules
				//here here
				
				if (streams.get(key).isFinIsSet()) {
					//If the connection is over, we print the stream
					System.out.println(streams.get(key).toString());
					//And we remove the connection from the hashtable
					connections.remove(key);
					streams.remove(key);
				}
				
			}
			else {
				//If this is the first time this packet is seen
					//It must be that the connection is establishing	
					
					//We create a new list of TCPPackets, and we add it to the hashtable
					ArrayList<TCPPacket> connection = new ArrayList<TCPPacket>();
					connection.add(packet);
					connections.put(key, connection);
					
					//we create a new stream from this packet, we add it to the hashtable
					Stream stream = new Stream(packet, "send");
					streams.put(key,stream);
					
					//We Check if the stream follow the rules
					//here here					
			}
		}
	}
}
