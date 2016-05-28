CFLAGS	= -Wall -g

frag: frag.o
	$(CC) $(CFLAGS) -o $(@) $(<) -lnfnetlink -lnetfilter_queue
