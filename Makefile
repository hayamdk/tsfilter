PROGRAM = tsfilter

SOURCES = tsfilter.c utils/aribstr.c
SOURCES_CP932 = utils/ts_parser.c utils/tsdstr.c core/default_decoder.c
OBJS = $(SOURCES:.c=.o)
OBJS_CP932 = $(SOURCES_CP932:.c=.o)

CC := gcc

CFLAGS = -Ofast -march=native -Wall -flto -I$(CURDIR)
#CFLAGS = -O0 -Wall -g -I$(CURDIR)

LDFLAGS = -flto

LDFLAGS := $(if $(shell uname -a | grep -i cygwin), $(LDFLAGS) -liconv, $(LDFLAGS))

$(OBJS_CP932): CHARSET_FLAG = -finput-charset=cp932
$(OBJS): CHARSET_FLAG = 

$(PROGRAM): $(OBJS) $(OBJS_CP932)
	$(CC) $(OBJS) $(OBJS_CP932) $(LDFLAGS) -o $(PROGRAM)

.c.o:
	$(CC) $(CFLAGS) $(CHARSET_FLAG) -c $< -o $@

.PHONY: clean

clean:
	rm -f $(PROGRAM) $(OBJS) $(OBJS_CP932)
