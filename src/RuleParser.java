import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Scanner;

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
		String host=null;Rule rule =null;
		try{
			s= new Scanner(new BufferedReader(new FileReader(filename)));
			while(s.hasNextLine()){
				String t =s.nextLine();
				if(t.contains("host"))
					host =initRule(t);
				else if(!t.isEmpty()){
					if(t.contains("name")){
						rule = new Rule();	
						rule.initHost(host);					
						String[] name = t.split("=");
						rule.setName(name[1]);
					}
					else if(t.contains("protocol")){
							ProtocolRule pr = new ProtocolRule();
							ArrayList<SubRule> sr = new ArrayList<SubRule>();
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
										SubRule sub = new SubRule();
									   ArrayList<String> flags = new ArrayList<String>();
										if(line.length > 2){ //has flags
											char[] f = line[2].toLowerCase().toCharArray();
											for(int c= 0; c< f.length; c++){
												flags.add(Flags.getFlag(f[c]));	
											}
										}
										if(title.equals("send")){
											sub.setReceived(false);
											String[] reg = value.split("with");
											sub.setData(reg[0].trim());
											if(flags!=null)
												sub.setFlags(flags);
										}

										else if(title.equals("recv")){
											sub.setReceived(true);
											String[] reg = value.split("with");
											sub.setData(reg[0].trim());
											if(flags!=null)
												sub.setFlags(flags);
										}
										sr.add(sub);
									}
								}
								else{
									break;
								}
							}		
									pr.setSubRule(sr);
									rule.setPrule(pr);
									rules.add(rule);				
					}

					else if(t.contains("tcp_stream")){
							StreamRule sr = new StreamRule();
							String title=null;
							String value=null;
							while (s.hasNextLine()){
								String l = s.nextLine();
								if(l.contains("=")){
									String[] line = l.split("=");
									title= line[0];
									value = line[1];
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
								}
							
								else{
									break;
								}

							}	
							rule.setSrule(sr);
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
