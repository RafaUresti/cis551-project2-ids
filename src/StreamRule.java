


public class StreamRule extends Rule {

	private String type ="tcp_stream";
	private String src_port;
	private String dst_port;
	private String ip;
	private boolean isReceive;
	private String data;
	
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

	public boolean isReceive() {
		return isReceive;
	}

	public void setReceive(boolean isReceive) {
		this.isReceive = isReceive;
	}

	public String getData() {
		return data;
	}

	public void setData(String data) {
		this.data = data;
	}

	public void print_rules() {
		super.print_rules();
		if(type != null)
			System.out.println("Rule Type : "+ type);
		if(src_port != null)
			System.out.println("Source Port : "+ src_port);
		if(dst_port!=null)
			System.out.println("Dest Port : "+ dst_port);
		if(ip!=null)
			System.out.println("IP : "+ ip);
		
		System.out.println((isReceive ?"Recv : \"" : "Send : \"")+ data+"\"");
	}
}
