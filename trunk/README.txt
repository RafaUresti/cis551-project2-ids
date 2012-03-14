IDS - The main class. It just instantiates the IDSPacketListener for further 
processing.

IDSPacketListener - Listens for packets and either delegates to the 
TCPRuleProcessor, or the UDPRuleProcessor for actual rule checking.

ProtocolRule - Class that represents a Protocol Rule. It extends Rule which 
contains basic information, and additional contains a list of sub rules.

Rule - Base class for all rules.  Contains basic information common to all 
rules.

RuleParser - Class responsible for parsing a rule file. It creates a list of 
rules that are later compared against packets. The rules
are left as a single list until they are provided to one of the 
RuleProcessors which will cache them appropriately.

StreamRule - Class that represents a Stream Rule.  It extends Rule which 
contains basic information, and additionally contains an indicator for 
Send/Receive as well as a regular expression for matching.

SubRule - Class that represents a sub-rule for a ProtocolRule.  It contains 
an indicator for Send/Recv a regular expression and an array of flags.

TCPRuleProcessor - Class that processes TCP rules.  For each session, a 
TCPSession object is created which manages the packets. Whenever a new 
TCP packet is received, it is added to the session and processed appropriately.
The Stream and Protocol rules are run against the stream each time a new 
packet is added, providing real-time alarms for rule violations.  
	- For TCP Protocol rules, rules that are currently in progress are held
	  in memory until the rule is violated, or the rule was found to not
	  be violated. As soon as the packet is examined, it is removed from the
	  list of packets that need to be processed. Rules are tracked similarly to
	  the UDPSession described below.
	- For Stream rules, the stream bytes are concatenated real-time in order
	  to provide a string to compare. The rules are compared against the string
	  being built with each packet received.

TCPSession - Class that keeps track of a TCP session. This class ensures that
packets are ordered correctly, that a sent packet is not processed a second
time because of a resend, etc.

UDPRuleProcessor - Class that processes UDP rules.  The UDPSession object keeps
track of rules that are currently in progress allowing for real time analysis 
of intrusion detection.  The algorithm is similar to that of the TCP Protocol
rules above.

UDPSession - Simple wrapper that keeps track of rules that are currently in
progress. If the same data is repeated multiple times in sub rules, there is a
possibility that the rule could be in progress multiple times at once, so a
Rule, to List of Sub Rule map is contained in the UDPSession in order to keep
track of all possible interpretations of the data with regard to the rule.