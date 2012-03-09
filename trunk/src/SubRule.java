import java.util.ArrayList;
import java.util.Iterator;


public class SubRule {

	private String snd;
	private String recv;
	private ArrayList<String> sndflags;	
	private ArrayList<String> recvflags;	
	
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

	public ArrayList<String> getSndflags() {
		return sndflags;
	}

	public void setSndflags(ArrayList<String> sndflags) {
		this.sndflags = sndflags;
	}

	public ArrayList<String> getRecvflags() {
		return recvflags;
	}

	public void setRecvflags(ArrayList<String> recvflags) {
		this.recvflags = recvflags;
	}
	public void print_rules() {
		if(snd!=null){
			System.out.println("Send : "+ snd);
		}
		if(recv!=null){
			System.out.println("Recv : "+ recv);
		}
		if(sndflags!=null){
			int c =0;
			for(Iterator<String> i= sndflags.iterator(); i.hasNext();){
				System.out.println("Send Flag "+ (c+1) +" "+i.next());
				c ++;
			}
		}
		if(recvflags!=null){
			int c =0;
			for(Iterator<String> i= recvflags.iterator(); i.hasNext();){
				System.out.println("Recv Flag "+ (c+1) +" "+i.next());
				c ++;
			}
		}
	}
}
