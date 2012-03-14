
JAVAC = javac -classpath lib/jpcap.jar	

compile:
	$(JAVAC) -b bin src/*.java
clean:
	$(RM) bin/*.class
run:
	./run.sh resource/trace1.pcap resource/rules.txt
