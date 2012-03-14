
/**
 *  Base class for all rules. Contains information
 *  common to all rules.
 */
public class Rule
{
	private String host; // the ip address of the host
	private String name; // the name of the rule that should be printed when a match occurs
	private String protocol; // UDP or TCP
	private String src_port; // The source port
	private String dst_port; // The destination port
	private String ip; // The IP address of the connecting host.
	
	public Rule() {
	}
	
	public void setHost(String host){
		this.host = host;
	}
	
	public String getHost() {
		return host;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
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

	public void print_rules(){
		if(host != null)
			System.out.println("Host : "+ host);
		if(name != null)
			System.out.println("Name : "+ name);
	}
}