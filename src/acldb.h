// Copyright (c) 2014 CosineCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ACLDB_H
#define ACLDB_H


#include "main.h"
#include "aclusers.h"
#include <db_cxx.h>


/** Access to the ACL database (acl.dat) */
class CACLDB {
	private:
		boost::filesystem::path pathACL;
	public:
		CACLDB();
		bool Write(const CACLUsers &users);
		bool Read(CACLUsers &users);
};


#endif // ACLDB_H
