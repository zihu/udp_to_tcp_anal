CXX=g++
LFLAGS=-lpcap -lpthread

OBJS=srcip_query_stats.o sitelist.o helper_func.o utility.o

PROG=srcip_query_stats

all: ${PROG}

${PROG}: ${OBJS}
	${CXX} -o $@ ${OBJS} ${LFLAGS} 

%.o: %.cc
	${CXX} -c $<

clean: 
	rm -rf ${OBJS} ${PROG}
