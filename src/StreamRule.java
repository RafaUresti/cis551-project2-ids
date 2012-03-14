import java.util.regex.Pattern;

/**
 * Class that represents a stream rule.
 * 
 * @author bbreck
 *
 */
public class StreamRule extends Rule {

	// Identifies this rule as a stream rule.
	private String type ="tcp_stream";
	// Determines whether this is a receive rule
	// or a send rule.
	private boolean isReceive;
	// The regular expression to look for.
	private String data;
	// The compiled regular expression.
	private Pattern pattern;
	public String getType() {
		return type;
	}
	
	public void setType(String type) {
		this.type = type;
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
		pattern = Pattern.compile(data);
	}

	public Pattern getPattern() {
		return pattern;
	}

	public void setPattern(Pattern pattern) {
		this.pattern = pattern;
	}

	public void print_rules() {
		super.print_rules();
		if(type != null)
			System.out.println("Rule Type : "+ type);
		if(getSrcPort() != null)
			System.out.println("Source Port : "+ getSrcPort());
		if(getDstPort()!=null)
			System.out.println("Dest Port : "+ getDstPort());
		if(getIp()!=null)
			System.out.println("IP : "+ getIp());
		
		System.out.println((isReceive ?"Recv : \"" : "Send : \"")+ data+"\"");
	}
}
