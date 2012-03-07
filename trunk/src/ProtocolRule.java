
public class ProtocolRule {

	private String type = "protocol";
	private String protocol;
	private String src_port;
	private String dst_port;
	private String ip;
	private SubRule sub_rule;
	
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getProtocol() {
		return protocol;
	}
	public void setProtocol(String protocol) {
		this.protocol = protocol;
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
	
	public SubRule getSubRule() {
		return sub_rule;
	}
	
	public void setSubRule(SubRule sub_rule) {
		this.sub_rule = sub_rule;
	}
}
