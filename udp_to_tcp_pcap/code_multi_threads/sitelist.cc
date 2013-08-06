#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include "sitelist.h"
#include "helper_func.h"
#include "utility.h"

tldList::tldList(const char *fname) {

    char buf[MAX_BUF_SIZE];
    std::ifstream f(fname, std::ios::in);
    if (!f) {
        std::cout << fname << ": " << strerror(errno) << std::endl;
	exit(1);
    }
    while(!f.eof())
    {
        f.getline(buf, sizeof(buf)-1);
		buf[strlen(buf)]='\0';

        // If starts with a # is a comment
        if ( (strlen(buf) > 0) && (buf[0] == '#') )
            continue;

        if (strlen(buf) > 0)
        {
            theSet.insert(tolower(buf));
        }

		memset(buf, 0, MAX_BUF_SIZE);
    }

    //std::cout << "read " << theSet.size() << " TLDs from " << fname << std::endl;
}

tldList::~tldList() {
	theSet.clear();
}


/*
 * The 'components' arg specifies how many components of
 * the name must match.  If zero then the entire name
 * must match.
 *
 * Assumes name doesn't have trailing dot.
 */
bool
tldList::match(const std::string& name, unsigned int components)
{
	if (0 == components)
		return (theSet.end() != theSet.find(tolower(name)));
	const char *t = name.c_str();
	const char *s = t + strlen(t);
	while (components && --s > t)
		if ('.' == *s)
			components--;
	if ('.' == *s)
		s++;
	return (theSet.end() != theSet.find(tolower(s)));
}
