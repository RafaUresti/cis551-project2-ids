import java.util.ArrayList;
import java.util.List;

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
	public List<Rule> parse()
	{
		return new ArrayList<Rule>();
	}
}
