
public class Flags {

	public static String a = "ack";
	public static String s = "syn";
	public static String f = "fin";
	public static String r = "rst";
	public static String p = "psh";
	public static String u = "urg";
	
	public static String getFlag(char ind) {
		String ret = null;
		switch (ind){
		case 'a':
				ret= a;
				break;
		case 's':
				ret = s;
				break;
		case 'f':
				ret = f;
				break;
		case 'r':
				ret = r;
				break;
		case 'u':
				ret = u;
				break;
		case 'p':
				ret = p;
				break;				
		default:
			ret= null;
			break;
		}
		return ret;
	}


}
