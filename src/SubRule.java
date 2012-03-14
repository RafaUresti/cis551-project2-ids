import java.util.regex.Pattern;

/**
 * Sub-rule of a ProtocolRule that defines what to look
 * for in a single packet.
 *
 */
public class SubRule {

	private String data; // regular expression to be matched.
	private Pattern pattern; // compiled version of the regular expression
	private boolean isReceived; // Determines if this is a Send or Receive rule.
	private char[] flags; // The flags to look for on a TCP Packet.
	
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

	public boolean isReceived() {
		return isReceived;
	}

	public void setReceived(boolean isReceived) {
		this.isReceived = isReceived;
	}

	public char[] getFlags() {
		return flags;
	}

	public void setFlags(char[] flags) {
		this.flags = flags;
	}

	public void print_rules() {
		System.out.println((isReceived ? "Recv : " : "Send : ")+ data);
		System.out.print(isReceived ? "Recv Flag : " : "Send Flag : ");
		System.out.println(flags != null ? new String(flags) : "");
	}
}
