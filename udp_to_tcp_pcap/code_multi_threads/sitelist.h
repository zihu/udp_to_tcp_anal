#ifndef TLDLIST_H
#define TLDLIST_H 1

/*
 * This class implements a list of TLD names.  It can read the list
 * from a file, and match an entry in the list.
 */

#include <map>
#include <set>
#include <string>


class tldList {
    private:
        std::set < std::string > theSet;
    public:
        tldList(const char *fname);
        ~tldList();
	bool match(const std::string& name, unsigned int components = 0);
	int get_tldlist_size() {return theSet.size(); }
};

#endif
