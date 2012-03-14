import java.util.ArrayList;
import java.util.Iterator;


public class ProtocolRule extends Rule {

	private String type = "protocol";
	private String protocol;
	private String src_port;
	private String dst_port;
	private String ip;
	private ArrayList<SubRule> sub_rule;
	
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
	
	public ArrayList<SubRule> getSubRule() {
		return sub_rule;
	}
	
	public void setSubRule(ArrayList<SubRule> sr) {
		this.sub_rule = sr;
	}
	public void print_rules() {
		super.print_rules();
		if(type != null)
			System.out.println("Rule Type : "+ type);
		if(protocol != null)
			System.out.println("Protocol : "+ protocol);
		if(src_port != null)
			System.out.println("Source Port : "+ src_port);
		if(dst_port!=null)
			System.out.println("Dest Port : "+ dst_port);
		if(ip!=null)
			System.out.println("IP : "+ ip);
		if(sub_rule!=null)
			for(Iterator<SubRule> i= sub_rule.iterator(); i.hasNext();){
				i.next().print_rules();
			}
		
	}
}
