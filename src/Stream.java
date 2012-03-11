import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Hashtable;

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
		}
		else {
			//This packet was sent by the host
			this.srcport = packet.getSourcePort();
			this.destport = packet.getDestinationPort();
			this.ip = packet.getDestinationAddress();
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
					this.recCurrentSeqNumber = this.recIniSeqNumber++;
				}
				else {
					//This is a data packet
					
					//We get back the data
					
					if (packet.getSequenceNumber()==this.recCurrentSeqNumber) {
						//If it is the next packet we are expecting
						System.out.println("packet expected");
						
						//We add the data
						if (dataRecv==null) {
							this.dataRecv = packet.getData();	
						}
						else {		
							this.dataRecv = ArrayHelper.join(this.dataRecv, packet.getData());	
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
					if (!(this.dataRecv==null)){
						//ASCII string of data received
						System.out.println("received :" + new String(dataRecv));
						
						//Hex version of data received
						String hexRes = null;
						for (int i=0; i<dataRecv.length; i++){
							hexRes+=Integer.toHexString(dataRecv[i]);
						}
						System.out.println("received to hex : "+ hexRes);
					}
					
					//Hex version of UTF-8 String version of "now I own your computer"
					String nowIown = "Now I own your computer";
					String nowIhex = String.format("%x", new BigInteger(nowIown.getBytes("UTF-8")));
					System.out.println("Hex value of nowIown : "+nowIhex);
					
				}
			}
			else {
				//This packet was sent by the host
				if (this.sendIniSeqNumber==-1) {
					//It must be the first packet sent
					this.sendIniSeqNumber = packet.getSequenceNumber();
					this.sendCurrentSeqNumber = this.sendIniSeqNumber++;
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
					if (!(this.dataSend==null)){
					System.out.println("Sent :" + new String(dataSend));
					}
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
		ret += "data sent : " + new String(dataSend) + "\n";
		}
		if (dataRecv!=null){
		ret += "data received : " + new String(dataRecv) + "\n";
		}
		return ret;
	}
}
