import java.util.ArrayList;
import java.util.Iterator;

/**
 * Class that represents a protocol rule.
 *
 */
public class ProtocolRule extends Rule {

	// Identifies this rule as a protocol rule.
	private String type = "protocol";
	// list of sub rules.
	private ArrayList<SubRule> sub_rule;
	
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
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
		if(getProtocol() != null)
			System.out.println("Protocol : "+ getProtocol());
		if(getSrcPort() != null)
			System.out.println("Source Port : "+ getSrcPort());
		if(getDstPort()!=null)
			System.out.println("Dest Port : "+ getDstPort());
		if(getIp()!=null)
			System.out.println("IP : "+ getIp());
		if(sub_rule!=null)
			for(Iterator<SubRule> i= sub_rule.iterator(); i.hasNext();){
				i.next().print_rules();
			}
		
	}
}
