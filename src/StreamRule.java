
public class StreamRule {

	private String type ="tcp_stream";
	private String src_port;
	private String dst_port;
	private String ip;
	private String snd;
	private String recv;
	
	public String getType() {
		return type;
	}
	
	public void setType(String type) {
		this.type = type;
	}
	
	public String getSrcPort() {
		return src_port;
	}
	
	public void setSrcPort(String src_port) {
		this.src_port = src_port;
	}
	
	public String getDstPort() {
		return dst_port;
	}
	
	public void setDstPort(String dst_port) {
		this.dst_port = dst_port;
	}
	
	public String getIp() {
		return ip;
	}
	
	public void setIp(String ip) {
		this.ip = ip;
	}
	
	public String getSnd() {
		return snd;
	}
	
	public void setSnd(String snd) {
		this.snd = snd;
	}
	
	public String getRecv() {
		return recv;
	}
	
	public void setRecv(String recv) {
		this.recv = recv;
	}
}
