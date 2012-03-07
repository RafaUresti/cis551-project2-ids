
import java.util.ArrayList;

public class Rule
{
	private String host ="192.168.0.1"; 				// the ip address of the host
	private String name; 				// the name of the rule that should be printed when a match occurs
	private StreamRule s_rule; 			//the stream rule
	private ProtocolRule p_rule;		//the protocol rule
	private SubRule sub_rule;			//the subrules to be matched
	private String text;				//the string that needs to be matched
	private String ip;					//the ip address
	private String port;				//the port number
	private String regex;				// the regular expression to be matched
	private ArrayList<String> flags;	//the flags to be matched
	
	public Rule(String host){
		this.host = host;
	}
	public String getHost() {
		return host;
	}
	public StreamRule getSrule() {
		return s_rule;
	}
	public void setSrule(StreamRule s_rule) {
		this.s_rule = s_rule;
	}
	public ProtocolRule getPrule() {
		return p_rule;
	}
	public void setPrule(ProtocolRule p_rule) {
		this.p_rule = p_rule;
	}
	public SubRule getSubrule() {
		return sub_rule;
	}
	public void setSubrule(SubRule sub_rule) {
		this.sub_rule = sub_rule;
	}
	public String getText() {
		return text;
	}
	public void setText(String text) {
		this.text = text;
	}
	public String getPort() {
		return port;
	}
	public void setPort(String port) {
		this.port = port;
	}
	public String getIp() {
		return ip;
	}
	public void setIp(String ip) {
		this.ip = ip;
	}
	public String getRegex() {
		return regex;
	}
	public void setRegex(String regex) {
		this.regex = regex;
	}
	public ArrayList<String> getFlags() {
		return flags;
	}
	public void setFlags(ArrayList<String> flags) {
		this.flags = flags;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
}