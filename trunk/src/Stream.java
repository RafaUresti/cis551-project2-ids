import java.lang.StringBuffer;

import com.sun.corba.se.impl.encoding.TypeCodeOutputStream;

import net.sourceforge.jpcap.net.TCPPacket;

public class Stream {
	
	private int srcport;
	private int destport;
	private String ip;
	
	private long sendIniSeqNumber;
	private StringBuffer send = new StringBuffer();
	
	private long recIniSeqNumber;
	private StringBuffer recv = new StringBuffer();
	
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

	public StringBuffer getSend() {
		return send;
	}

	public void setSend(StringBuffer send) {
		this.send = send;
	}

	public StringBuffer getRecv() {
		return recv;
	}

	public void setRecv(StringBuffer recv) {
		this.recv = recv;
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
			this.recIniSeqNumber = packet.getSequenceNumber();
		}
		else {
			//This packet was sent by the host
			this.srcport = packet.getSourcePort();
			this.destport = packet.getDestinationPort();
			this.ip = packet.getDestinationAddress();
			this.sendIniSeqNumber = packet.getSequenceNumber();
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
				if (packet.isSyn()) {
					//It must be the answer to the first Syn
					this.recIniSeqNumber = packet.getSequenceNumber();
				}
				else {
					//This is a data packet
					
					//We compute the offset
					long seq = packet.getSequenceNumber();
					int offset = (int) (seq - this.recIniSeqNumber-1);
					
					//We get back the data and cast it into a string
					String data =  new String(packet.getData());
					if (offset>this.recv.length()){
						this.recv.append(data);
					}
					else {
						this.recv.insert(offset, data);
					}
					System.out.println(this.recv.toString());
				}
			}
			else {
				//This packet was sent by the host
				if (packet.isSyn()) {
					//It must be the answer to the first Syn
					this.sendIniSeqNumber = packet.getSequenceNumber();
				}
				else {
					//This is a data packet
					
					//We compute the offset
					long seq = packet.getSequenceNumber();
					int offset = (int) (seq - this.sendIniSeqNumber);
					
					//We get back the data and cast it into a string
					String data =  new String(packet.getData());
					if (offset>this.send.capacity()) {
						this.recv.append(data);
					}
					else {
						this.recv.insert(offset, data);
						System.out.println(this.recv.toString());
					}
				}
			}
		}
	}
	
	public String toString () {
		String ret = "srcport : " + this.srcport + "\n";
		ret += "destport : " + this.destport + "\n";
		ret += "ip : " + this.ip + "\n";
		ret += "data sent : " + this.send.toString() + "\n";
		ret += "data received : " + this.recv.toString() + "\n";
		
		return ret;
	}
}
