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
//#include <unordered_map>
#include <vector>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "sitelist.h"
#include "utility.h"
using namespace std;
unsigned long total_query=0;
string prev_src="";
unsigned long prev_qtime=0;
tldList *sitelist = 0;
map<string, int> src_ival;
vector<unsigned long> qinval_arr;
list<unsigned long> tcp_conn;
unsigned long query_count=0;
unsigned long RTT=50;

int
options(int argc, char *argv[])
{
    static struct option longopts[] = 
	{
  	  {"iplist-file", required_argument, NULL, 'I'},
      {"RTT", required_argument, NULL, 'R'},
	  {NULL, 0, NULL, 0}
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "I:R:", longopts, NULL)) != -1) {
	switch (ch) {
	case 'I':
	    sitelist = new tldList(optarg);
	    break;
    case 'R':
        RTT = atoi(optarg);
        break;
	default:
		cout << "usage: " << argv[0]
		<< " --iplist-file=file"
        << " --RTT=rtt"
		<< endl;
	    exit(1);
	}
    }
    return optind;
}


//according to the ts of the next query, to decide if we need a new tcp connection or we can reuse the previous ones;
void update_tcpconn(unsigned long next_query_ts)
{
    bool get_free_tcpconn=false;
    if(tcp_conn.size()==0)
    {
        tcp_conn.push_back(next_query_ts);
    }
    else
    {
        list<unsigned long>::iterator tit;
        for(tit=tcp_conn.begin(); tit!=tcp_conn.end(); ++tit)
        {
            //if the query in that tcp connection ends, reuse the tcp connection 
            unsigned long cur_query_ts = *tit;
            //second to ms.
            unsigned long diff=(next_query_ts- cur_query_ts)*1000;
            if( diff > RTT)
            {
                *tit = next_query_ts;
                get_free_tcpconn = true;
                break;
            }
        }

        if(!get_free_tcpconn)
        {
            tcp_conn.push_back(next_query_ts);
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
	unsigned long qtime=atol(sItem[1].c_str());

	//check if dst ip belongs to one of .com .net server; 
    //ignore the record if the dst ip neither belongs to a .com server or a .net server.
	if(sitelist)
	{
		if(!sitelist->match(sItem[2]))
		{
			sItem.clear();
			return;
		}
	}
	
	if(prev_src.size()==0)
    {
        //first record; 
        tcp_conn.clear();
		prev_src=sItem[0];
        //prev_qtime=qtime;
        tcp_conn.push_back(qtime);
        query_count=1;
    }
	else
	{
        if(prev_src!=sItem[0])
        {
            /*
            //src ip changed; compute the average query interval for the current src ip;
            //compute median and mean 
            if(qinval_arr.size()>0)
            {
                double mean=compute_mean(qinval_arr);
                double median=compute_median(qinval_arr);
                printf("%s\t%.4f\t%.4f\t%lu\n", prev_src.c_str(), mean, median, qinval_arr.size()+1);
            }
            */


            //print out the result
            //"src_ip" "# of tcp connections" "# of queries"
            printf("%s\t%lu\t%lu\n", prev_src.c_str(), tcp_conn.size(), query_count);


            //start statistics for the new src ip;
            tcp_conn.clear();
            prev_src=sItem[0];
            query_count=1;
            tcp_conn.push_back(qtime);

            //qinval_arr.clear();
            //prev_qtime=qtime;
        }
        else
        {
            //to see if we need build a new tcp connection or not? 
            //and also update the tcp connection list. 
            update_tcpconn(qtime);
            query_count +=1;


            /*
            //same src ip, sum the query interval.
            unsigned long qival = qtime-prev_qtime;
            qinval_arr.push_back(qival);
            prev_qtime=qtime;
            */
        }
	}

	sItem.clear();
}




/*
void print_tld_queries()
{
	map<string, int>::iterator mit;
	for(mit = tld_queries.begin(); mit!=tld_queries.end(); ++mit)
	{
		printf("%s\t%d\n", (mit->first).c_str(), mit->second);
	}
}
*/

int
main(int argc, char *argv[])
{

   
    int i;
    i = options(argc, argv);
    argc -= i;
    argv += i;

    //print header information;
    //printf("#srcip\tmean\tmedian\tqcount\n");
    
	char buf[MAX_BUF_SIZE];
	memset(buf, 0, MAX_BUF_SIZE);
	while(fgets(buf, MAX_BUF_SIZE, stdin))
	{
		buf[strlen(buf)-1]='\0';
		per_record(buf);
		memset(buf, 0, MAX_BUF_SIZE);
	}

    //print the last ip's stats information;
    printf("%s\t%lu\t%lu\n", prev_src.c_str(), tcp_conn.size(), query_count);

    /*
    if(qinval_arr.size()>0)
    {
        double mean=compute_mean(qinval_arr);
        double median=compute_median(qinval_arr);
        printf("%s\t%.4f\t%.4f\t%lu\n", prev_src.c_str(), mean, median, qinval_arr.size()+1);
    }
    */

     tcp_conn.clear();
	
	if(sitelist)
		delete sitelist;
	return 1;
}
