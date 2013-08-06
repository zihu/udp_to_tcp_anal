DATAFILE=tcpconn_cdf.dat
RTT=50
SITE=nyc3
DAY=20130710

GRAPHDIR=${DAY}_${SITE}
GRAPH=tcpconn_cdf.eps
DATA=${GRAPHDIR}/${DATAFILE}

SERVERLIST=server.iplist

DATA_PROCESS_PROG=srcip_query_stats
CDF_DATA_MAKER=mk_cdf_data.pl

ADD_JAR=add-jar.hiveql
CREAT_PCAP_TABLE=creat_pcap_table.hiveql
CREAT_PCAP_TABLE_TEMPLATE=creat_pcap_table.hiveql.template
CREAT_TEMP_TABLE=creat_temp_table.hiveql

QUERY_TEMPLATE=query.hiveql.template
QUERY=query2.hiveql

PLOT_SCRIPT=plot.gnu

HIVE_CMD=hive -f /dev/fd/0


DATA_ORG_DIR=/user/dnscaps/dnscaps
DATA_DST_DIR=/user/zhu/udp_to_tcp_anal/data

servers: ${SERVERLIST}

data: ${DATA}

plot: ${GRAPH}

script: ${QUERY} ${CREAT_PCAP_TABLE}

all: plot

test:
	true

${CREAT_PCAP_TABLE}: ${CREAT_PCAP_TABLE_TEMPLATE}
	sed 's/YYYYMMDD/${DAY}/g; s/SITE/${SITE}/g' ${CREAT_PCAP_TABLE_TEMPLATE} > $@ 

${QUERY}: ${QUERY_TEMPLATE}
	for (( c=1; c<2; c++));\
	do \
		sed "s/WHICHPART/%$$c/g" ${QUERY_TEMPLATE} >> $@_; \
	done
	test -s $@_ && mv $@_ $@
	

${SERVERLIST}:
	for f in a b c d e f g h i j k l m ; do host $$f.gtld-servers.net | awk '{if($$3 == "IPv6") {print $$5;} else {print $$4;}}' ; done > $@_
	test -s $@_ && mv $@_ $@

${GRAPHDIR}:
	mkdir ${GRAPHDIR}

${DATA_PROCESS_PROG}:
	cd ./code && make clean all && mv $@ ../ && cd -

${DATA}: ${GRAPHDIR} ${ADD_JAR} ${CREAT_PCAP_TABLE} ${QUERY} ${DATA_PROCESS_PROG} ${CDF_DATA_MAKER} ${SERVERLIST}
	cat ${ADD_JAR} ${CREAT_PCAP_TABLE} | ${HIVE_CMD}
	cat ${ADD_JAR} ${QUERY} | ${HIVE_CMD} | ./${DATA_PROCESS_PROG} -I ${SERVERLIST} -R ${RTT} | sort -k 3 -rn | ./mk_cdf_data.pl > $@_
	test -s $@_ && mv $@_ $@

${GRAPH}:${DATA} ${PLOT_SCRIPT} ${GRAPHDIR}
	cp ${PLOT_SCRIPT} ${GRAPHDIR}
	cd ${GRAPHDIR} && gnuplot ${PLOT_SCRIPT} > $@_ 
	test -s $@_ && mv $@_ $@ cd -

clean:
	rm -rf ${GRAPHDIR} ${SERVERLIST} ${DATA_PROCESS_PROG} ${CREAT_PCAP_TABLE} ${QUERY}
