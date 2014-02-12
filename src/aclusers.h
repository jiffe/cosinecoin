// Copyright (c) 2014 CosineCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ACLUSERS_H
#define ACLUSERS_H


#include <map>
#include <vector>
#include "sync.h"
#include "acluser.h"


class CACLUsers {
	private:
		// critical section to protect the inner data structures
		mutable CCriticalSection cs;
		
		CACLUser globalUser;
		
		// table with information about all nIds
		std::map<std::string, CACLUser> mapUsers;
		
	public:
		CACLUsers();
		json_spirit::Value Dump();
		
		CACLUser auth(const std::string credentials, IPv6Address ip_address);
		
		// Create an entry
		bool Create(const std::string username, const std::string password, uint64 perms, bool global = false);
		bool Remove(const std::string username);
		
		bool Update(const std::string username, const std::string password);
		
		bool Enable(const std::string username);
		bool Disable(const std::string username);
		
		bool Grant(const std::string username, const std::string perm);
		bool Revoke(const std::string username, const std::string perm);
		
		bool AddNetwork(const std::string username, const std::string networkstr);
		bool DeleteNetwork(const std::string username, const std::string networkstr);
		
		bool AddAccount(const std::string username, std::string account, std::string permission);
		bool DeleteAccount(const std::string username, std::string account);
		
		bool flush();
		
		IMPLEMENT_SERIALIZE (
			{
				LOCK(cs);
				unsigned char nVersion = 0;
				READWRITE(nVersion);
				READWRITE(mapUsers);
			}
		)
		
};


extern CACLUsers aclusers;


#endif // ACLUSERS_H
