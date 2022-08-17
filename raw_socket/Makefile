MAIN=my_ping.c
INET_INCLUDES=./stack_headers
UTIL_INCLUDES=./utility_functions
UTIL_FILE=./utility_functions/*.c
OUTFILE=my_ping


compile: $(MAIN) $(UTIL_FILE) $(INET_INCLUDES)/*.h $(UTIL_INCLUDES)/*.h
	gcc -o $(OUTFILE) $(MAIN) $(UTIL_FILE) -I$(UTIL_INCLUDES) -I$(INET_INCLUDES)

clean: 
	rm -r $(OUTFILE) 