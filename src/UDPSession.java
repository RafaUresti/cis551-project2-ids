import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class UDPSession {

	// Map that keeps track of rules in progress
	private Map<Rule, List<Integer>> udpMap;
	
	public UDPSession()
	{
		udpMap = new HashMap<Rule, List<Integer>>();
	}

	public Map<Rule, List<Integer>> getUdpMap() {
		return udpMap;
	}

	public void setUdpMap(Map<Rule, List<Integer>> udpMap) {
		this.udpMap = udpMap;
	}
	
	
}
