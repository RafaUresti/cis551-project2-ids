import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.regex.*;


import net.sourceforge.jpcap.util.ArrayHelper;
import net.sourceforge.jpcap.net.TCPPacket;

public class Stream {
	
	private int srcport;
	private int destport;
	private String ip;
	
	private long sendSeqNumber=-1;
	private byte[] dataSend = null;

	//data sent to early (is it possible ?)
	private Hashtable<Long, byte[]> dataSentWait = new Hashtable<Long, byte[]>();
	
	private long recSeqNumber=-1;
	private byte[] dataRecv = null;

	//data received to early ()
	private Hashtable<Long, byte[]> dataRecvWait = new Hashtable<Long, byte[]>();
	
	private boolean finIsSet = false;
	
	private int count = 0;
	
	public int getSrcport() {
		return srcport;
	}

	public int getDestport() {
		return destport;
	}

	public String getIp() {
		return ip;
	}

	public boolean isFinIsSet() {
		return finIsSet;
	}

	//Constructor to initialize the stream
	public Stream (TCPPacket packet, boolean received) {
		if (received) {
			//This packet was received by the host
			this.srcport = packet.getDestinationPort();
			this.destport = packet.getSourcePort();
			this.ip = packet.getSourceAddress();
		}
		else {
			//This packet was sent by the host
			this.srcport = packet.getSourcePort();
			this.destport = packet.getDestinationPort();
			this.ip = packet.getDestinationAddress();
		}
		if (!packet.isSyn()) {
			if (packet.getData().length!=0) {this.dataRecv = packet.getData();}
		}
	}
	
	//Constructor do add a new packet to the stream
	public void addPacket (TCPPacket packet, boolean received) throws UnsupportedEncodingException {
		count++;
		if (packet.isFin()||packet.isRst()) {
			//The communication is over
			this.finIsSet = true; 
		}
		else {
			if (received) {
				//This packet was received by the host
				if (this.recSeqNumber==-1) {
					//It must be the first received packet
					this.recSeqNumber = packet.getSequenceNumber();
					if (packet.isSyn()) {this.recSeqNumber = this.recSeqNumber+1;}
					else {
						//We add the data
						if (dataRecv==null) {
							if (packet.getData().length!=0) {this.dataRecv = packet.getData();}	
						}
						else {
							if (packet.getData().length!=0) {
							this.dataRecv = ArrayHelper.join(this.dataRecv, packet.getData());
							}
						}
						this.recSeqNumber = this.recSeqNumber+packet.getData().length;
					}				
				}
				else {
					//This is a data packet
					
					//We get back the data
					
					if (packet.getSequenceNumber()==this.recSeqNumber) {
						//If it is the next packet we are expecting
//						System.out.println("packet expected");
						
						//We add the data
						if (dataRecv==null) {
							if (packet.getData().length!=0) {this.dataRecv = packet.getData();}
						}
						else {		
							if (packet.getData().length!=0) {
								this.dataRecv = ArrayHelper.join(this.dataRecv, packet.getData());
							}	
						}
						
						//We now wait for the next packet
						this.recSeqNumber+= packet.getData().length;
					}					
					else {
						//The packet we were expecting has been delayed, or arrived earlier
						
						//We keep this packet inside our hashtable
						this.dataRecvWait.put(packet.getSequenceNumber(), packet.getData());
						
						//We call the function to check if the right packet(s) arrived earlier
						this.gatherData("recv");
					}
				}
			}
			else {
				//This packet was sent by the host
				if (this.sendSeqNumber==-1) {
					//It must be the first packet sent
					this.sendSeqNumber = packet.getSequenceNumber();
					if (packet.isSyn()) {this.sendSeqNumber = this.sendSeqNumber+1;}
					else {this.sendSeqNumber = this.sendSeqNumber+packet.getData().length;}	
				}
				else {
					//This is a data packet
					if (packet.getSequenceNumber()==this.sendSeqNumber) {
						
						if (this.dataSend==null) {
							this.dataSend = packet.getData();	
						}
						else {		
							this.dataSend = ArrayHelper.join(this.dataSend, packet.getData());
						}
						
						//We now wait for the next packet
						this.sendSeqNumber+= packet.getData().length;
					}
					else {
						//The packet we were expecting has been delayed, or arrived earlier
						
						//We keep this packet inside our hashtable
						this.dataRecvWait.put(packet.getSequenceNumber(), packet.getData());
							
						//We call the function to check if the right packet(s) arrived earlier
						this.gatherData("send");
					}
				}
			}
		}
	}
	
	public int size() {
		return count;
	}
	
	//Function to get back data from the inner hashtable
	private void gatherData (String recvORsend) {
		if (recvORsend.equals("recv")) {
			//We compute the received data
			while (this.dataRecvWait.containsKey(this.recSeqNumber)) {
				byte[] dataToadd = this.dataRecvWait.get(this.recSeqNumber);
				//We add the data		
				this.dataRecv = ArrayHelper.join(this.dataRecv, dataToadd);				
				this.recSeqNumber+=dataToadd.length;
			}
		}
		else {
			//We compute the sent data
			while (this.dataSentWait.containsKey(this.sendSeqNumber)) {
				byte[] dataToadd = this.dataSentWait.get(this.sendSeqNumber);
				//We add the data		
				this.dataSend = ArrayHelper.join(this.dataSend, dataToadd);
				this.sendSeqNumber++;
			}
		}
	} 
	
	public String toString () {
		String ret = "srcport : " + this.srcport + "\n";
		ret += "destport : " + this.destport + "\n";
		ret += "ip : " + this.ip + "\n";
		if (dataSend!=null){
		try {
			ret += "data sent : " + new String(dataSend, "ISO-8859-1") + "\n";
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		}
		if (dataRecv!=null){
		try {
			ret += "data received : " + new String(dataRecv, "ISO-8859-1") + "\n";
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		}
		return ret;
	}
	
	//Check if a given stream matches some TCP stream rule(s)
	public ArrayList<Rule> matchesRules(List<Rule> ruleSet) {
		ArrayList<Rule> matchedRules = new ArrayList<Rule>();
		Rule currentRule;
		StreamRule currentStreamRule;
		boolean destportMatch = false;
		boolean srcportMatch = false;
		boolean ipMatch = false;
		boolean firstMatch = false;
		boolean recMatch= false;
		boolean sendMatch= false;
		Pattern recPattern;
		Pattern sendPattern;
		Matcher m;
		Iterator<Rule> nextRule = ruleSet.listIterator();
		
		while (nextRule.hasNext()) {
			
			currentRule = nextRule.next();
			//We only want to test 
			if (currentRule instanceof StreamRule) {
				currentStreamRule = (StreamRule)currentRule;
				
				if (currentStreamRule.getSrcPort().equals("any")) {
					srcportMatch = true;
				}
				else {
					srcportMatch = currentStreamRule.getSrcPort().equals(Integer.toString(this.getSrcport()));
				}
				
				if (currentStreamRule.getDstPort().equals("any")) {
					destportMatch = true;
				}
				else {
					destportMatch = currentStreamRule.getDstPort().equals(Integer.toString(this.getDestport()));
				}
				
				if (currentStreamRule.getIp().equals("any")) {
					ipMatch = true;
				}
				else {
					ipMatch = currentStreamRule.getIp().equals(this.getIp());
				}
				
				firstMatch = srcportMatch&&destportMatch&&ipMatch;
				
				//If the first elements of the rule are matched, then we can try to match the regular expression(s)
				if (firstMatch) {
					
					//Regular expression over what is received
					if (currentStreamRule.isReceive()) {
						recPattern = Pattern.compile(currentStreamRule.getData());
						String rec = null;
						if (this.dataRecv!=null) {
							try {
								rec = new String (this.dataRecv, "ISO-8859-1");
							} catch (UnsupportedEncodingException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}	
						}
						
						if (rec!=null) {
							
							m = recPattern.matcher(rec);
							recMatch = m.find();	
						}
					}
					else {
						recMatch =true;
					}
					
					//Regular expression over what is sent
					if (!currentStreamRule.isReceive()) {
						sendPattern = Pattern.compile(currentStreamRule.getData());
						String sen = null;
						try {
							if (dataSend!=null) {
								sen = new String (this.dataSend, "ISO-8859-1");	
							}
						} catch (UnsupportedEncodingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						if (sen!=null) {
							m = sendPattern.matcher(sen);
							sendMatch = m.find();	
						}
					}
					else {
						sendMatch = true;
					}
					//If everything is matched
					if (recMatch&&sendMatch) {						
						//We add the rule that was matched to the list
						matchedRules.add(currentRule);
					}
				}
				
			}
		}
		return matchedRules;
	}
}
