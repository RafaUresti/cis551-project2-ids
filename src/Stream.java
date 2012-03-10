import java.lang.StringBuffer;

import java.util.Hashtable;

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

	public void setSrcport(int srcport) {
		this.srcport = srcport;
	}

	public int getDestport() {
		return destport;
	}

	public void setDestport(int destport) {
		this.destport = destport;
	}

	public String getIp() {
		return ip;
	}

	public void setIp(String ip) {
		this.ip = ip;
	}

	public boolean isFinIsSet() {
		return finIsSet;
	}

	public void setFinIsSet(boolean finIsSet) {
		this.finIsSet = finIsSet;
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
	public void addPacket (TCPPacket packet, String recORsent) {
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
					System.out.println(this.recIniSeqNumber);
					System.out.println(this.recCurrentSeqNumber);
					System.out.println(packet.getSequenceNumber());
					
					//We get back the data
					
					if (packet.getSequenceNumber()==this.recCurrentSeqNumber) {
						//If it is the next packet we are expecting
						System.out.println("packet expected");
						
						//We add the data
						if (dataRecv==null) {
							this.dataRecv = packet.getData();	
						}
						else {
							byte[] newDataArray = new byte[this.dataRecv.length+packet.getData().length];
							System.arraycopy(this.dataRecv, 0, newDataArray, 0, this.dataRecv.length);
							System.arraycopy(packet.getData(), 0, newDataArray, this.dataRecv.length, packet.getData().length);		
							this.dataRecv = newDataArray;	
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
					System.out.println("received :" + new String(dataRecv));
					}
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
							byte[] newDataArray = new byte[this.dataSend.length+packet.getData().length];
							System.arraycopy(this.dataSend, 0, newDataArray, 0, this.dataSend.length);
							System.arraycopy(packet.getData(), 0, newDataArray, this.dataSend.length, packet.getData().length);		
							this.dataSend = newDataArray;	
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
					
					System.out.println("Sent :" + new String(dataSend));
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
				byte[] newDataArray = new byte[this.dataRecv.length+dataToadd.length];
				System.arraycopy(this.dataRecv, 0, newDataArray, 0, this.dataRecv.length);
				System.arraycopy(dataToadd, 0, newDataArray, this.dataRecv.length, dataToadd.length);		
				this.dataRecv = newDataArray;
				
				this.recCurrentSeqNumber+=dataToadd.length;
			}
		}
		else {
			//We compute the sent data
			while (this.dataSentWait.containsKey(this.sendCurrentSeqNumber)) {
				byte[] dataToadd = this.dataSentWait.get(this.sendCurrentSeqNumber);
				//We add the data
				byte[] newDataArray = new byte[this.dataSend.length+dataToadd.length];
				System.arraycopy(this.dataSend, 0, newDataArray, 0, this.dataSend.length);
				System.arraycopy(dataToadd, 0, newDataArray, this.dataSend.length, dataToadd.length);		
				this.dataSend = newDataArray;
				
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
