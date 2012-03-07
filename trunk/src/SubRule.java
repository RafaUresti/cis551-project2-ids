import java.util.ArrayList;


public class SubRule {

	private String snd;
	private String recv;
	private ArrayList<String> flags;	
	
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

	public ArrayList<String> getFlags() {
		return flags;
	}

	public void setFlags(ArrayList<String> flags) {
		this.flags = flags;
	}
}
