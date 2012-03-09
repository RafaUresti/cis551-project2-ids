

public class Rule
{
	private String host; // the ip address of the host
	private String name; 				// the name of the rule that should be printed when a match occurs
	private StreamRule s_rule; 			//the stream rule
	private ProtocolRule p_rule;		//the protocol rule
	
	
	public Rule() {
	}
	
	public void initHost(String host){
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
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}

	public void print_rules(){
		if(host != null)
			System.out.println("Host : "+ host);
		if(name != null)
			System.out.println("Name : "+ name);
		if(s_rule!=null)
		  print_strules(s_rule);
		if(p_rule!=null)
			print_prules(p_rule);
		}
	
		private void print_prules(ProtocolRule p_rule2) {			
			p_rule2.print_rules();
			
		}
		private void print_strules(StreamRule s_rule2) {
			
			s_rule2.print_rules();
			
		}
	
}