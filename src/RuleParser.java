import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Scanner;

/**
 * Class responsible for parsing rule files. 
 *
 */
public class RuleParser
{
	private String filename;
	String currLine;

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
	public ArrayList<Rule> parse() throws IOException
	{
		Scanner s=null;
		ArrayList<Rule> rules = new ArrayList<Rule>();
		String host=null;
		String ruleName=null;
		try{
			s= new Scanner(new BufferedReader(new FileReader(filename)));
			while(s.hasNextLine()){
				String t =s.nextLine();
				// Get the host.
				if(t.contains("host"))
					host =initRule(t);
				else if(!t.isEmpty()){
					// Get the name of the rule.
					if(t.contains("name")){					
						String[] name = t.split("=");
						ruleName = name[1];
					}
					// Process a protocol rule.
					else if(t.contains("protocol")) {
						Rule rule = createProtocolRule(s);
						rule.setName(ruleName);
						rule.setHost(host);
						rules.add(rule);
					}

					// Process a stream rule.
					else if(t.contains("tcp_stream")) {
						Rule rule = createStreamRule(s);
						rule.setName(ruleName);
						rule.setHost(host);
						rules.add(rule);
					}
								
				}
			}
		return rules;
		}
		finally{
			if(s!=null)
				s.close();
		}
	}
	/**
	 * Parses a protocol rule.
	 * 
	 * @param s
	 * @return
	 */
	private ProtocolRule createProtocolRule(Scanner s)
	{
		ProtocolRule pr = new ProtocolRule();
		ArrayList<SubRule> sr = new ArrayList<SubRule>();
		pr.setSubRule(sr);
		String title=null;
		String value=null;
		while (s.hasNextLine()){
			String l = s.nextLine();
			if(l.contains("=")){
				String[] line = l.split("=");
				title= line[0].trim();
				value = line[1].trim();
				if(title.equals("src_port"))
					pr.setSrcPort(value);
				if(title.equals("dst_port"))
					pr.setDstPort(value);
				if(title.equals("ip"))
					pr.setIp(value);
				if(title.equals("proto"))
					pr.setProtocol(value);
				if(title.equals("send")||title.equals("recv")){
					sr.add(createSubRule(line, s));
				}
			}
			else{
				break;
			}
		}		
		return pr;
	}
	
	/**
	 * Parses a sub rule.
	 * 
	 * @param line
	 * @param s
	 * @return
	 */
	private SubRule createSubRule(String[] line, Scanner s)
	{
		SubRule sub = new SubRule();
		char[] flags = null; 
			// Get the flags.
			if(line.length > 2){ //has flags
				flags = line[2].toCharArray();
			}
			// Determine whether it is a send or receive.
			if(line[0].trim().equals("recv")){
				sub.setReceived(true);
			}
			String[] reg = line[1].trim().split("with");
			String data = reg[0].trim();
			sub.setData(data.substring(1, data.length()-1));
			// If there are flags set them.
			if(flags!=null)
				sub.setFlags(flags);
			// If the with clause was specified and no flags
			// were set, add an empty array.
			else if (reg.length == 2)
				sub.setFlags(new char[0]);
		return sub;
	}
	
	/**
	 * Parse a stream rule.
	 * 
	 * @param s
	 * @return
	 */
	private StreamRule createStreamRule(Scanner s)
	{
		StreamRule sr = new StreamRule();
		String title=null;
		String value=null;
		while (s.hasNextLine()){
			String l = s.nextLine();
			if(l.contains("=")){
				String[] line = l.split("=");
				title= line[0].trim();
				value = line[1].trim();
				if(title.equals("src_port"))
					sr.setSrcPort(value);
				if(title.equals("dst_port"))
					sr.setDstPort(value);
				if(title.equals("ip"))
					sr.setIp(value);
				if(title.equals("send"))
					// Strip the quotes.
					sr.setData(value.substring(1, value.length()-1));
				if(title.equals("recv"))
				{
					sr.setData(value.substring(1, value.length()-1));
					// Identify the rule as a receive rule.
					sr.setReceive(true);
				}
			}
		
			else{
				break;
			}

		}
		return sr;
	}

	/**
	 * Get the host from the file.
	 * 
	 * @param nextLine
	 * @return
	 */
	private String initRule(String nextLine) {
		String[] h = nextLine.split("=");
		String value = h[1];
		if(!nextLine.isEmpty())
			return value.trim();
		else{
			System.out.println("Rule syntax failed, first line should be host");
			System.exit(0);
		}
		return null;

	}

	
}
