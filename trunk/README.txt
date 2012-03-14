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
packet is added, providing real-time alarms for rule violations.  For TCP
Protocol rules, older packets are tossed once they have been processed in 
order to minimize processing time.  For Stream rules, the stream is
continuously concatenated in order to provide quick comparisons.

TCPSession - Class that keeps track of a TCP session. This class ensures that
packets are reordered correctly, that a sent packet is not processed a second
time because of a resend, etc.

UDPRuleProcessor - Class that processes UDP rules.  The UDPSession object keeps
track of rules that are currently in progress allowing for real time analysis 
of intrusion detection.

UDPSession - Simple wrapper that keeps track of rules that are currently in
progress. If the same data is repeated multiple times in sub rules, there is a
possibility that the rule could be in progress multiple times at once, so a
Rule, to List of Sub Rule map is contained in the UDPSession in order to keep
track of all possible interpretations of the data with regard to the rule.