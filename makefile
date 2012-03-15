
JAVAC = javac -classpath lib/jpcap.jar -d	

compile:
	$(JAVAC) bin src/*.java
clean:
	$(RM) bin/*.class
run:
	java -classpath bin:$(CLASSPATH) $(TRACE) $(RULES)
