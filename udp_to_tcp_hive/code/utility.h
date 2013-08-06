#ifndef UTILITY_H
#define UTILITY_H 1

/*
 * some utility functions 
 */

#include <map>
#include <set>
#include <string>
#include <vector>
#include <numeric>
#define MAX_BUF_SIZE 4096

using namespace std;
void Splitstring(char* cStr, char* cDelim, vector<string> &sItemVec);
double compute_median(vector<unsigned long>& arr);
double compute_mean(vector<unsigned long>& arr);

#endif
