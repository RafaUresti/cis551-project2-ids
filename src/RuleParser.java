import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class RuleParser
{
	private String filename;

    /**
     * Constructor that takes the name of the file to be parsed.
     */
	public RuleParser(String filename)
	{
		this.filename = filename;
	}
	
	/**
	 * Parses the file and creates a list of rules.
     */
	public List<Rule> parse() throws IOException
	{
		Scanner s=null;
		ArrayList<Rule> rules;
		try{
			s= new Scanner(new BufferedReader(new FileReader(filename)));
			s.useDelimiter("\n");
			while(s.hasNextLine()){
				getData(s.nextLine());
			}
		}
		finally{
			if(s!=null)
				s.close();
		}
		return new ArrayList<Rule>();
	}

	private void getData(String nextLine) {
		
	Scanner s= new Scanner(nextLine);
	Rule r = new Rule();
	String title=null;
	String value=null;
	s.useDelimiter("=");
	if(s.hasNext()){
		title= s.next().trim();
		value = s.next().trim();
	}
		if(title.equals("host"))
			r=new Rule(value);
		if(title.equals("name"))
			r.setName(value);
		if(title.equals("type"))
			if(value.equals("protocol")){
				createProtocolRule(s.nextLine());
			}
			else if(value.equals("tcp_stream"))
				createStreamRule(s.nextLine());
			
	}
	
	public StreamRule createStreamRule(String nxtLine){
		Scanner s= new Scanner(nxtLine);
		StreamRule sr = new StreamRule();
		String title=null;
		String value=null;
		s.useDelimiter("=");
		if(s.hasNext()){
			title= s.next().trim();
			value = s.next().trim();
		}
			if(title.equals("src_port"))
				sr.setSrcPort(value);
			if(title.equals("dst_port"))
				sr.setDstPort(value);
			if(title.equals("ip"))
				sr.setIp(value);
			if(title.equals("send"))
				sr.setSnd(value);
			if(title.equals("recv"))
				sr.setRecv(value);
			
		return sr;
	}

	public ProtocolRule createProtocolRule(String nxtLine){
		Scanner s= new Scanner(nxtLine);
		ProtocolRule pr = new ProtocolRule();
		String title=null;
		String value=null;
		s.useDelimiter("=");
		if(s.hasNext()){
			title= s.next().trim();
			value = s.next().trim();
		}
			if(title.equals("src_port"))
				pr.setSrcPort(value);
			if(title.equals("dst_port"))
				pr.setDstPort(value);
			if(title.equals("ip"))
				pr.setIp(value);
			if(title.equals("protocol"))
				pr.setProtocol(value);
			//if(title.equals("subrule"))
				//pr.setSubRule(sub_rule)(value);
			
		
			return pr;
	}
	
}
