MAIN=my_ping.c
INCLUDES=./stack_headers/
OUTFILE=my_ping


compile: $(MAIN) $(INCLUDES)
	gcc -o $(OUTFILE) $(MAIN) -I$(INCLUDES)

clean:
	rm $(OUTFILE)