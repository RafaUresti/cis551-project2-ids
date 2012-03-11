import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Pattern;


public class SubRule {

	private String data;
	private Pattern pattern;
	private boolean isReceived;
	private ArrayList<String> flags;
	
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

	public ArrayList<String> getFlags() {
		return flags;
	}

	public void setFlags(ArrayList<String> flags) {
		this.flags = flags;
	}

	public void print_rules() {
		System.out.println((isReceived ? "Recv : " : "Send : ")+ data);
		
		int c =0;
		for(Iterator<String> i= flags.iterator(); i.hasNext();){
			System.out.println((isReceived ? "Recv Flag : " : "Send Flag : ")+ 
								(c+1) +" "+i.next());
			c ++;
		}
	}
}
