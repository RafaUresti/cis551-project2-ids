import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import net.sourceforge.jpcap.net.TCPPacket;
import java.util.Hashtable;


public class StreamRuleProcessor
{
	private List<Rule> rules;
	private ArrayList<Rule> matchedRules = new ArrayList<Rule> ();
	private Hashtable<String, ArrayList<TCPPacket>> connections = new Hashtable<String, ArrayList<TCPPacket>>();
	private Hashtable<String, Stream> streams = new Hashtable<String, Stream>();
	private String host = "192.168.0.1";
	
	public StreamRuleProcessor(List<Rule> rules)
	{
		this.rules = rules;
	}
	
	public void processRules(TCPPacket packet)
	{
//		System.out.println("Stream Processing: "+
//				packet.toColoredVerboseString(true));

		if (packet.getDestinationAddress().equals(host))
		{//This packet has been received by the host
			
			//We generate a key which will identify the stream
			String key = packet.getSourceAddress() + ":" +
					packet.getDestinationPort() + ":" +
					packet.getSourcePort();
			
			if (connections.containsKey(key)) { 
				//There is a stream that corresponds to this packet
				
				//We add the packet to the corresponding list of packets
				connections.get(key).add(packet);
				
				//We add the packet to the new stream
				try {
					streams.get(key).addPacket(packet, "recv");
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				
				//We check if the stream match some rule(s)
				this.matchedRules = streams.get(key).matchesRules(this.rules);
				//We print the matched rules
				if (!this.matchedRules.isEmpty()) {
					//We print out the corresponding connection and the number of packets that were received during this connection
					System.out.println("Key :" + key);
					System.out.println("Number of packets received during this connection : "+ this.connections.get(key).size());
					Iterator<Rule> itRule = this.matchedRules.iterator();
					while (itRule.hasNext()) {
						System.out.println("Rule matched : "+ itRule.next().getName());
					}
				}
				//Then we can empty the matchedRules list
				this.matchedRules.clear();
				
				if (streams.get(key).isFinIsSet()) {
					//If the connection is over, we print the stream
					System.out.println("*****Stream over*****");
					streams.get(key).toString();
					//And we remove the connection from the hashtables
					connections.remove(key);
					streams.remove(key);
				}
			}
			else {
				//If this is the first time this packet is seen
					
					//We create a new list of TCPPackets, and we add it to the hashtable
					ArrayList<TCPPacket> connection = new ArrayList<TCPPacket>();
					connection.add(packet);
					connections.put(key, connection);
					
					//we create a new stream from this packet, we add it to the hashtable
					Stream stream = new Stream(packet, "recv");
					streams.put(key,stream);
					
					//We check if the stream match some rule(s)
					this.matchedRules = streams.get(key).matchesRules(this.rules);
					//We print the matched rules
					if (!this.matchedRules.isEmpty()) {
						System.out.println("Key :" + key);
						System.out.println("Number of packets received during this connection : "+ this.connections.get(key).size());
						Iterator<Rule> itRule = this.matchedRules.iterator();
						while (itRule.hasNext()) {
							System.out.println("Rule matched : "+ itRule.next().getName());
						}
					}
					//Then we can empty the matchedRules list
					this.matchedRules.clear();
			}
		}
		else {//This packet has been sent by the host
			
			//We generate a key which will identify the stream
			String key = packet.getDestinationAddress() + ":" +
					packet.getSourcePort() + ":" +
					packet.getDestinationPort();
			
			if (connections.containsKey(key)) { 
				//There is a stream that corresponds to this packet
				
				//We add the packet to the corresponding list of packets
				connections.get(key).add(packet);
				
				//We add the packet to the new stream
					try {
						streams.get(key).addPacket(packet, "send");
					} catch (UnsupportedEncodingException e) {
						e.printStackTrace();
					}
				
				
				//We check if the stream match some rule(s)
				this.matchedRules = streams.get(key).matchesRules(this.rules);
				//We print the matched rules
				if (!this.matchedRules.isEmpty()) {
					System.out.println("Key :" + key);
					System.out.println("Number of packets received during this connection : "+ this.connections.get(key).size());
					Iterator<Rule> itRule = this.matchedRules.iterator();
					while (itRule.hasNext()) {
						System.out.println("Rule matched : "+ itRule.next().getName());
					}
				}
				//Then we can empty the matchedRules list
				this.matchedRules.clear();
				
				if (streams.get(key).isFinIsSet()) {
					//If the connection is over, we print the stream
					System.out.println("*****Stream over*****");
					streams.get(key).toString();
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
					
					//We check if the stream match some rule(s)
					this.matchedRules = streams.get(key).matchesRules(this.rules);
					//We print the matched rules
					if (!this.matchedRules.isEmpty()) {
						System.out.println("Key :" + key);
						System.out.println("Number of packets received during this connection : "+ this.connections.get(key).size());
						Iterator<Rule> itRule = this.matchedRules.iterator();
						while (itRule.hasNext()) {
							System.out.println("Rule matched : "+ itRule.next().getName());
						}
					}
					//Then we can empty the matchedRules list
					this.matchedRules.clear();
			}
		}
	}
}
