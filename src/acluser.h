// Copyright (c) 2014 CosineCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ACLUSER_H
#define ACLUSER_H


#include <stdint.h>
#include <string>
#include <vector>
#include "util.h"

#include "ipv6address.h"

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"


#define ACLPERM_GETWORK (1 << 0)


class CACLAccount {
	public:
		std::string accountName;
		uint8_t flags;
		
		CACLAccount() { }
		CACLAccount(std::string accountName, uint8_t flags) : accountName(accountName), flags(flags) { }
		
		json_spirit::Value Dump();
		
		IMPLEMENT_SERIALIZE (
			{
				READWRITE(accountName);
				READWRITE(flags);
			}
		)
};


class CACLUser {
	private:
		std::string username;
		std::string password;
		uint64 perms;
		bool enabled;
		std::vector <IPv6Address> locations;
		std::map <std::string, uint8_t> accounts;
		
	public:
		CACLUser();
		CACLUser(const std::string username, const std::string password, uint64 perms, bool enabled = true);
		
		bool update(std::string password);
		
		bool auth(const std::string username, const std::string password, IPv6Address ip_address);
		
		json_spirit::Value Dump();
		bool enable();
		bool disable();
		bool grant(std::string perm);
		bool revoke(std::string perm);
		
		bool addNetwork(IPv6Address network);
		bool deleteNetwork(IPv6Address network);
		
		bool addAccount(std::string accountName, uint8_t flags);
		bool deleteAccount(std::string accountName);
		
		bool isEnabled();
		
		bool check(uint64 permission);
		bool checkAccount(std::string accountName, uint8_t permission);
		
		IMPLEMENT_SERIALIZE (
			{
				READWRITE(username);
				READWRITE(password);
				READWRITE(perms);
				READWRITE(enabled);
				READWRITE(locations);
				READWRITE(accounts);
			}
		)
		
};


#endif // ACLUSER_H
