#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <getopt.h>
#include <time.h>
#include <string.h>

#include <iostream>
#include <fstream>
#include <iomanip>
#include <map>
#include <list>
#include <pthread.h>
#include <vector>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "sitelist.h"
#include "utility.h"
//#include "pcap_layers.h"
using namespace std;

#define MAX_UNIQ_IP 10000000
#define MAX_THREAD 10000

unsigned long total_query=0;
unsigned long uniq_td_index=0;
char* pcap_file_name=NULL;
string prev_src="";
unsigned long prev_qtime=0;
tldList *sitelist = 0;
map<string, int> src_ival;

pthread_mutex_t mutex_for_print = PTHREAD_MUTEX_INITIALIZER;


typedef vector<double> ts_vec;
ts_vec qts_vec;

unsigned long RTT=50;

typedef struct paras_
{
	string ip;
	ts_vec tsvec;
} paras;

paras parameters[MAX_THREAD];
pthread_t thread_IDs[MAX_THREAD];

static void (*handle_datalink) (const u_char * pkt, int len, void *userdata, const struct pcap_pkthdr* hdr)= NULL;

int
options(int argc, char *argv[])
{
    static struct option longopts[] = 
	{
	  {"pcap-file", required_argument, NULL, 'f'}, 
  	  {"iplist-file", required_argument, NULL, 'I'},
      {"RTT", required_argument, NULL, 'R'},
	  {NULL, 0, NULL, 0}
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "I:R:f:", longopts, NULL)) != -1) {
	switch (ch) {
	case 'I':
	    sitelist = new tldList(optarg);
	    break;
    case 'R':
        RTT = atoi(optarg);
        break;
	case 'f':
		pcap_file_name=strdup(optarg);
		break;	
	default:
		cout << "usage: " << argv[0]
		<< " --iplist-file=file"
        << " --RTT=rtt"
		<< " --pcap-file=pcapfile"
		<< endl;
	    exit(1);
	}
    }
    return optind;
}


//according to the ts of the next query, to decide if we need a new tcp connection or we can reuse the previous ones;
void update_tcpconn(double next_query_ts,list<double>* tcp_conn )
{
    bool get_free_tcpconn=false;
    if(tcp_conn->size()==0)
    {
        tcp_conn->push_back(next_query_ts);
    }
    else
    {
        list<double>::iterator tit;
        for(tit=tcp_conn->begin(); tit!=tcp_conn->end(); ++tit)
        {
            //if the query in that tcp connection ends, reuse the tcp connection 
            double cur_query_ts = *tit;
            //second to ms.
            double diff=(next_query_ts- cur_query_ts)*1000;
            if( diff > RTT)
            {
				//printf("%f\t%f\n", next_query_ts, cur_query_ts);
                *tit = next_query_ts;
                get_free_tcpconn = true;
                break;
            }
        }

        if(!get_free_tcpconn)
        {
            tcp_conn->push_back(next_query_ts);
        }
        
    }
}

//compute how many tcp connections needed for that src IP
void compute_tcpconn(string ip, ts_vec* tslist)
{   
	sort(tslist->begin(), tslist->end());
    unsigned long query_count=0;
	list<double> tcp_conn;
    tcp_conn.clear();
    ts_vec::iterator tsit;
    for(tsit=tslist->begin(); tsit!=tslist->end(); ++tsit)
    {
        query_count+=1;
        update_tcpconn(*tsit, &tcp_conn);
    }   
    
    //header: "src_ip" "# of tcp connections" "# of queries"
	pthread_mutex_lock( &mutex_for_print);
    printf("%s\t%lu\t%lu\n", ip.c_str(), tcp_conn.size(), query_count);
	pthread_mutex_unlock( &mutex_for_print);
	tcp_conn.clear();
}


void* tcpconn_model(void* args)
{
	paras* arguments = (paras*) args;
	compute_tcpconn(arguments->ip, &(arguments->tsvec));
	(arguments->ip).clear();
	(arguments->tsvec).clear();
	pthread_exit(NULL);
}

void fork_thread()
{
	paras* args=  &parameters[uniq_td_index];
	int ret = pthread_create(&thread_IDs[uniq_td_index], NULL, tcpconn_model, static_cast<void*>(args));

	//pthread_t t;
	//int ret = pthread_create(&t, NULL, tcpconn_model, static_cast<void*>(&arguments));
	//pthread_join(thread_IDs[uniq_td_index], NULL);
	if(ret!=0)
		fprintf(stderr, "create thread failed: %s\n", (args->ip).c_str());


	uniq_td_index++;
	if(uniq_td_index>= MAX_THREAD)
	{
		for(int i=0; i< uniq_td_index; i++)
		{
			pthread_join(thread_IDs[i], NULL);
			(parameters[i].ip).clear();
			(parameters[i].tsvec).clear();
		}
		uniq_td_index=0;
	}
}


//process queries one by one
void per_record(double qtime, string srcIP, string dstIP)
{
	//check if dst ip belongs to one of .com .net server; 
    //ignore the record if the dst ip neither belongs to a .com server or a .net server.
	if(sitelist)
	{
		if(!sitelist->match(dstIP))
		{
			return;
		}
	}
	
	if(prev_src.size()==0)
    {
        //first record; 
		prev_src=srcIP;
		qts_vec.push_back(qtime);
    }
	else
	{
        if(prev_src!=srcIP)
        {
			parameters[uniq_td_index].ip=prev_src;
			parameters[uniq_td_index].tsvec=qts_vec;
            //fork a thread to analyze the queries for the previous IP address
			fork_thread();

            //start statistics for the new src ip;
            qts_vec.clear(); 
            prev_src=srcIP;
			qts_vec.push_back(qtime);
        }
        else
        {
			qts_vec.push_back(qtime);
        }
	}
}


//process queries one by one
void per_record(char* tldrecord)
{
	char delim[]=" \t";
	vector<string> sItem;
	sItem.clear();
	Splitstring(tldrecord, delim, sItem);	
	if(sItem.size()!=3)
		return;

	string srcIP=sItem[1];
	string dstIP=sItem[2];
	string ts=sItem[0];
	double qtime=atof(ts.c_str());
	per_record(qtime, srcIP, dstIP);
	sItem.clear();
}


void handle_ipv4(const struct ip * ip, int len, void *userdata, const struct pcap_pkthdr* hdr)
{

	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip->ip_src), sourceIp, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip->ip_dst), destIp, INET_ADDRSTRLEN);
	double qtime= hdr->ts.tv_sec + (double)hdr->ts.tv_usec/1000000;
	per_record(qtime, sourceIp, destIp);
	//printf("%lu\t%lu\t%f\t%s\t%s\t%d\n", hdr->ts.tv_sec, hdr->ts.tv_usec,qtime, sourceIp, destIp, INET_ADDRSTRLEN);
}

void handle_ipv6(const struct ip6_hdr* ip6, int len, void *userdata, const struct pcap_pkthdr* hdr)
{

	char sourceIp[INET6_ADDRSTRLEN];
	char destIp[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &(ip6->ip6_src), sourceIp, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(ip6->ip6_dst), destIp, INET6_ADDRSTRLEN);
	double qtime= hdr->ts.tv_sec + (double)hdr->ts.tv_usec/1000000;
	per_record(qtime, sourceIp, destIp);
	//printf("%lu\t%lu\t%s\t%s\t%d\n", hdr->ts.tv_sec, hdr->ts.tv_usec, sourceIp, destIp, INET6_ADDRSTRLEN);
}

void handle_ip(const struct ip *ip, int len, void *userdata, const struct pcap_pkthdr* hdr)
{
    /* note: ip->ip_v does not work if header is not int-aligned */
    switch ((*(uint8_t *) ip) >> 4) {
    case 4:
    handle_ipv4(ip, len, userdata, hdr);
    break;
    case 6:
    handle_ipv6((struct ip6_hdr *)ip, len, userdata, hdr);
    break;
    default:
	fprintf(stderr, "Only support IPv4 or IPv6\n");
    break;
    }   
}

void handle_raw(const u_char * pkt, int len, void *userdata, const struct pcap_pkthdr* hdr)
{
   handle_ip((struct ip *)pkt, len, userdata, hdr);
}


void handle_ether(const u_char * pkt, int len, void *userdata, const struct pcap_pkthdr* hdr)
{
	struct ether_header *e = (struct ether_header *)pkt;
	if (len < ETHER_HDR_LEN)
		return;
	pkt += ETHER_HDR_LEN;
	len -= ETHER_HDR_LEN;
	if (len < 0)
		return;
	handle_ip((struct ip *)pkt, len, userdata, hdr);
}



int
main(int argc, char *argv[])
{

    int i;
    i = options(argc, argv);
    argc -= i;
    argv += i;

	unsigned long records=0;
	pcap_t *in=NULL;
	struct pcap_pkthdr hdr;
	char errbuf[PCAP_ERRBUF_SIZE+1];
 
	if(pcap_file_name == NULL)
	{
		fprintf(stderr, "empty pcap file name\n");
		return -1;
	}
	// open capture file for offline processing
	in = pcap_open_offline(pcap_file_name, errbuf);
	if (in == NULL) {
		fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
		return -1;
	}
 

	//figure out the datalink type
	switch (pcap_datalink(in))
	{
		case DLT_RAW:
			fprintf(stderr, "DLT_RAW\n");
			handle_datalink=handle_raw;
			break;
		case DLT_EN10MB: 
			fprintf(stderr, "DLT_EN10MB\n");
			handle_datalink=handle_ether;
			break;
		default:
			fprintf(stderr, "unsupported data link type\n");
			exit(1);
			break;
	}

	// start packet processing loop, just like live capture
	const u_char *data;
	while ((data = pcap_next(in, &hdr))) 
	{
		records++;
		handle_datalink(data, hdr.caplen, NULL, &hdr);
		if(records%200000==0)
			fprintf(stderr, "processed %lu queries\n", records);

	}
	fprintf(stderr, "In total: %lu queries in the file: %s\n", records, pcap_file_name);
	compute_tcpconn(prev_src, &qts_vec);
	
	//for(int i=0; i< uniq_td_index; i++)
	//{
	//	pthread_join(thread_IDs[i], NULL);
	//}

	qts_vec.clear();
	if(sitelist)
		delete sitelist;

	return 1;
}
