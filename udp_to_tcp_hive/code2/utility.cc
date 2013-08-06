#include <stdlib.h>
#include "utility.h"
//split a string to an vector;
void Splitstring(char* cStr, char* cDelim, vector<string> &sItemVec)
{
	char* p;
	p=strtok(cStr, cDelim);
	while (p!=NULL)
	{
		sItemVec.push_back(p);
		p=strtok(NULL, cDelim);
	}
}


//compute median of an array
double compute_median(vector<unsigned long>& arr)
{
  double median;
  size_t size = arr.size();

  sort(arr.begin(), arr.end());

  if (size  % 2 == 0)
  {
      median = (arr[size / 2 - 1] + arr[size / 2]) / 2;
  }
  else 
  {
      median = arr[size / 2];
  }
  return median; 
}

//compute the mean of an array
double compute_mean(vector<unsigned long>& arr)
{
    size_t size = arr.size();
    double sum = accumulate(arr.begin(), arr.end(), 0.0);
    double mean = sum / size;
    return mean;
}
