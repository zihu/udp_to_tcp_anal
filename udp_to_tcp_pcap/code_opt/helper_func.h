#ifndef HELPER_FUNC_H
#define HELPER_FUNC_H 1

#if INACTIVE
#include <math.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

// query rate to logarithmic bin
unsigned int qr2bin(double qr);

double bin2qr(int bin);

double get_perc(uint64_t a, uint64_t b);

double timeval_subtract (struct timeval *x, struct timeval *y);

bool is_rfc1918(IN_ADDR addr);

uint8_t qtype_to_xtype(uint8_t qtype);

uint8_t xtype_to_qtype(uint8_t xtype);
#endif

#include <string>
std::string tolower (const std::string & s);

#endif
