

public class Rule
{
	private String host; // the ip address of the host
	private String name; // the name of the rule that should be printed when a match occurs
	
	public Rule() {
	}
	
	public void setHost(String host){
		this.host = host;
	}
	
	public String getHost() {
		return host;
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
	}
}