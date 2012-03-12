import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
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
	
	private long sendIniSeqNumber=-1;
	private long sendCurrentSeqNumber=-1;
	private byte[] dataSend = null;

	//data sent to early (is it possible ?)
	private Hashtable<Long, byte[]> dataSentWait = new Hashtable<Long, byte[]>();
	
	private long recIniSeqNumber=-1;
	private long recCurrentSeqNumber=-1;
	private byte[] dataRecv = null;

	//data received to early ()
	private Hashtable<Long, byte[]> dataRecvWait = new Hashtable<Long, byte[]>();
	
	private boolean finIsSet = false;
	
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
	public Stream (TCPPacket packet, String recORsent) {
		if (recORsent.equals("recv")) {
			//This packet was received by the host
			this.srcport = packet.getDestinationPort();
			this.destport = packet.getSourcePort();
			this.ip = packet.getSourceAddress();
			
			if (!packet.isSyn()) {
				if (packet.getData().length!=0) {this.dataRecv = packet.getData();}
			}
		}
		else {
			//This packet was sent by the host
			this.srcport = packet.getSourcePort();
			this.destport = packet.getDestinationPort();
			this.ip = packet.getDestinationAddress();
			
			if (!packet.isSyn()) {
				if (packet.getData().length!=0) {this.dataRecv = packet.getData();}
			}
		}
	}
	
	//Constructor do add a new packet to the stream
	public void addPacket (TCPPacket packet, String recORsent) throws UnsupportedEncodingException {
		if (packet.isFin()||packet.isRst()) {
			//The communication is over
			this.finIsSet = true; 
		}
		else {
			if (recORsent.equals("recv")) {
				//This packet was received by the host
				if (this.recIniSeqNumber==-1) {
					//It must be the first received packet
					this.recIniSeqNumber = packet.getSequenceNumber();
					if (packet.isSyn()) {this.recCurrentSeqNumber = this.recIniSeqNumber+1;}
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
						this.recCurrentSeqNumber = this.recIniSeqNumber+packet.getData().length;
					}				
				}
				else {
					//This is a data packet
					
					//We get back the data
					
					if (packet.getSequenceNumber()==this.recCurrentSeqNumber) {
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
						this.recCurrentSeqNumber+= packet.getData().length;
					}					
					else {
						//The packet we were expecting has been delayed, or arrived earlier
						
						//We keep this packet inside our hashtable
						this.dataRecvWait.put(packet.getSequenceNumber(), packet.getData());
						
						//We call the function to check if the right packet(s) arrived earlier
						this.gatherData("recv");
					}
					String test = null;
					
//					if (!(this.dataRecv==null)){
//						//ASCII string of data received
////						System.out.println("received :" + new String(dataRecv, "ISO-8859-1"));
////						
//						//Hex version of data received
//						
////						String hexRes = null;
////						for (int i=0; i<dataRecv.length; i++){
////							hexRes+=Integer.toHexString(dataRecv[i]);
////						}
////						System.out.println("received to hex : "+ hexRes);
//					
//					
////					byte[] backTobytes = new byte[hexRes.length()/2];
////					int j = 0;
////					for (int i =; i<hexRes.length();i+=2){
////						backTobytes[j++] = Byte.parseByte(hexRes.substring(i , i+2) , 16);
////					}
////					test = new String (backTobytes, "ISO-8859-1");
////					System.out.println("Test : "+test);
////					
//					}
////					Hex version of UTF-8 String version of "now I own your computer"
//					String nowIown = "Now I own your computer";
//					String nowIhex = String.format("%x", new BigInteger(nowIown.getBytes("ISO-8859-1")));
//					System.out.println("Hex value of nowIown : "+nowIhex);
				}
			}
			else {
				//This packet was sent by the host
				if (this.sendIniSeqNumber==-1) {
					//It must be the first packet sent
					this.sendIniSeqNumber = packet.getSequenceNumber();
					if (packet.isSyn()) {this.sendCurrentSeqNumber = this.sendIniSeqNumber+1;}
					else {this.sendCurrentSeqNumber = this.sendIniSeqNumber+packet.getData().length;}	
				}
				else {
					//This is a data packet
					if (packet.getSequenceNumber()==this.sendCurrentSeqNumber) {
						
						if (this.dataSend==null) {
							this.dataSend = packet.getData();	
						}
						else {		
							this.dataSend = ArrayHelper.join(this.dataSend, packet.getData());
						}
						
						//We now wait for the next packet
						this.sendCurrentSeqNumber+= packet.getData().length;
					}
					else {
						//The packet we were expecting has been delayed, or arrived earlier
						
						//We keep this packet inside our hashtable
						this.dataRecvWait.put(packet.getSequenceNumber(), packet.getData());
							
						//We call the function to check if the right packet(s) arrived earlier
						this.gatherData("send");
					}
//					if (!(this.dataSend==null)){
//				//		System.out.println("Sent :" + new String(dataSend));
//					}
				}
			}
		}
	}
	
	//Function to get back data from the inner hashtable
	private void gatherData (String recvORsend) {
		if (recvORsend.equals("recv")) {
			//We compute the received data
			while (this.dataRecvWait.containsKey(this.recCurrentSeqNumber)) {
				byte[] dataToadd = this.dataRecvWait.get(this.recCurrentSeqNumber);
				//We add the data		
				this.dataRecv = ArrayHelper.join(this.dataRecv, dataToadd);				
				this.recCurrentSeqNumber+=dataToadd.length;
			}
		}
		else {
			//We compute the sent data
			while (this.dataSentWait.containsKey(this.sendCurrentSeqNumber)) {
				byte[] dataToadd = this.dataSentWait.get(this.sendCurrentSeqNumber);
				//We add the data		
				this.dataSend = ArrayHelper.join(this.dataSend, dataToadd);
				this.sendCurrentSeqNumber++;
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
			if (currentRule.getSrule()!=null) {
				currentStreamRule = currentRule.getSrule();
				
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
					if (currentStreamRule.getRecv()!=null) {
						recPattern = Pattern.compile(currentStreamRule.getRecv().substring(1,currentStreamRule.getRecv().length()-1));
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
					if (currentStreamRule.getSnd()!=null) {
						sendPattern = Pattern.compile(currentStreamRule.getSnd().substring(1,currentStreamRule.getSnd().length()-1));
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
