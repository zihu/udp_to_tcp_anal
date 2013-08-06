#include "helper_func.h"
#include <algorithm>

#if INACTIVE
// query rate to logarithmic bin
unsigned int
qr2bin(double qr)
{
    double x = log(qr * 1000) / log(10);
    int b = int (ceil(x));
    if (b < 0)
        b = 0;
    return b;
}

double
bin2qr(int bin)
{
    if (bin < 0)
        return 0.0;
    return pow(10.0, (double)bin) / 1000.0;
}

double
get_perc(uint64_t a, uint64_t b)
{
    if (0 == b)
        return 0.0;

    double r = ((double)a/(double)b)*100;

    return r;
}

double
timeval_subtract (struct timeval *x, struct timeval *y)
{
    double r, rx, ry;

    rx = x->tv_sec + ((double) x->tv_usec / 1000000);
    ry = y->tv_sec + ((double) y->tv_usec / 1000000);

    r = ry - rx;

    return r;
}

bool
is_rfc1918(IN_ADDR addr)
{
    if (4 != addr.version())
	return false;

    // RFC1918 address space
    unsigned int net10 = 0x0A000000;   // 10/8
    unsigned int net172 = 0xAC100000;  // 172.16/12
    unsigned int net192 = 0xC0A80000;  // 192.168/16

    unsigned long clt_addr = ntohl(addr.v4().s_addr);
    if ( ( clt_addr & 0xff000000) == net10 )
        return true;
    if ( ( clt_addr & 0xfff00000) == net172 )
        return true;
    if ( ( clt_addr & 0xffff0000) == net192 )
        return true;

    return false;
}

uint8_t
qtype_to_xtype(uint8_t qtype)
{
    switch (qtype) {
        case ns_t_a:
        return 1;
        case ns_t_ns:
        return 2;
        case ns_t_cname:
        return 3;
        case ns_t_soa:
        return 4;
        case ns_t_ptr:
        return 5;
        case ns_t_mx:
        return 6;
        case ns_t_txt:
        return 7;
        case ns_t_aaaa:
        return 8;
        case ns_t_srv:
        return 9;
        case 38:	/* A6 */
        return 10;
        case 24:	/* SIG */
        return 11;
        case 25:	/* KEY */
        return 12;
        case 30:	/* NXT */
        return 13;
        case 46:	/* RRSIG */
        return 14;
        case 47:	/* NSEC */
        return 15;
        case 48:	/* DNSKEY */
        return 16;
        case 50:	/* NSEC3 */
        return 17;
        default:
        return 18;
    }
}

uint8_t
xtype_to_qtype(uint8_t xtype)
{
    switch (xtype) {
        case 1:
        return ns_t_a;
        case 2:
        return ns_t_ns;
        case 3:
        return ns_t_cname;
        case 4:
        return ns_t_soa;
        case 5:
        return ns_t_ptr;
        case 6:
        return ns_t_mx;
        case 7:
        return ns_t_txt;
        case 8:
        return ns_t_aaaa;
        case 9:
        return ns_t_srv;
        case 10:
        return 38;	/* A6 */
        case 11:
        return 24;	/* SIG */
        case 12:
        return 25;	/* KEY */
        case 13:
        return 30;	/* NXT */
        case 14:
        return 46;	/* RRSIG */
        case 15:
        return 47;	/* NSEC */
        case 16:
        return 48;	/* DNSKEY */
        case 17:
        return 50;	/* NSEC3 */
        case 18:
        default:
        return 0;
    }
}

#endif

// returns a lower case version of the string 
std::string tolower (const std::string & s) {
  std::string d (s);
  transform (d.begin (), d.end (), d.begin (), (int(*)(int)) tolower);
  return d;
}
