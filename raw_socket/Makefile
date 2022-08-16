MAIN=my_ping.c
INET_INCLUDES=./stack_headers/
UTIL_INCLUDES=./utility_functions/
UTIL_FILE=./utility_functions/util_func.c 
OUTFILE=my_ping


compile: $(MAIN) $(UTIL_FILE) $(INCLUDES)
	gcc -o $(OUTFILE) $(MAIN) $(UTIL_FILE) -I$(INET_INCLUDES) -I$(UTIL_INCLUDES)

clean:
	rm $(OUTFILE)