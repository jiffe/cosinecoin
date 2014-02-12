#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/foreach.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "aclusers.h"
#include "hash.h"
#include "acldb.h"
#include "bitcoinrpc.h"

#include <iomanip>


CACLUsers aclusers;


/***************************************************************************************************
*
*
***************************************************************************************************/
CACLUsers::CACLUsers() {
	this->globalUser = CACLUser("", "", 0, false);
}


/***************************************************************************************************
*
*
***************************************************************************************************/
CACLUser CACLUsers::auth(const std::string credentials, IPv6Address ip_address) {
	
	std::vector<std::string> tokens;
    split(tokens, credentials, boost::algorithm::is_any_of(":"));
	if(tokens.size() != 2) {
		return CACLUser();
	}
	
	if(this->globalUser.auth(tokens[0], tokens[1], ip_address))
		return this->globalUser;
	
	typedef std::map<std::string, CACLUser> usermap;
	BOOST_FOREACH(usermap::value_type &user, this->mapUsers) {
		if(user.second.auth(tokens[0], tokens[1], ip_address))
			return user.second;
	}
	
	return CACLUser();
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::Create(const std::string username, const std::string password, uint64 perms, bool global) {
	if(global) {
		this->globalUser = CACLUser(username, Hash(password.begin(), password.end()).GetHex(), perms);
		//this->globalUser.addNetwork(__builtin_bswap32(inet_addr("127.0.0.1")), 0xff000000);
		return true;
	}
	this->mapUsers[username] = CACLUser(username, Hash(password.begin(), password.end()).GetHex(), perms);
	return this->flush();
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::Remove(const std::string username) {
	this->mapUsers.erase(username);
	return this->flush();
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::Enable(const std::string username) {
	std::map<std::string, CACLUser>::const_iterator it = this->mapUsers.find(username);
	if(it != this->mapUsers.end()) {
		if(this->mapUsers[username].enable()) {
			return this->flush();
		}
	}
	return false;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::Disable(const std::string username) {
	std::map<std::string, CACLUser>::const_iterator it = this->mapUsers.find(username);
	if(it != this->mapUsers.end()) {
		if(this->mapUsers[username].disable()) {
			return this->flush();
		}
	}
	return false;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::Grant(const std::string username, const std::string perm) {
	std::map<std::string, CACLUser>::const_iterator it = this->mapUsers.find(username);
	if(it == this->mapUsers.end()) {
		throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid username!");
	}
	if(!this->mapUsers[username].grant(perm)) {
		throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid permission!");
	}
	return this->flush();
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::Revoke(const std::string username, const std::string perm) {
	std::map<std::string, CACLUser>::const_iterator it = this->mapUsers.find(username);
	if(it != this->mapUsers.end()) {
		if(this->mapUsers[username].revoke(perm)) {
			return this->flush();
		}
	}
	return false;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::Update(const std::string username, const std::string password) {
	std::map<std::string, CACLUser>::const_iterator it = this->mapUsers.find(username);
	if(it != this->mapUsers.end()) {
		if(this->mapUsers[username].update(Hash(password.begin(), password.end()).GetHex())) {
			return this->flush();
		}
	}
	return false;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::AddNetwork(const std::string username, const std::string networkstr) {
	std::map<std::string, CACLUser>::const_iterator it = this->mapUsers.find(username);
	if(it != this->mapUsers.end()) {
		IPv6Address network = networkstr;
		if(!network.isValid()) {
			throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid network parameter!"));
		}
		
		if(this->mapUsers[username].addNetwork(network)) {
			return this->flush();
		}
	}
	return false;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::DeleteNetwork(const std::string username, const std::string networkstr) {
	std::map<std::string, CACLUser>::const_iterator it = this->mapUsers.find(username);
	if(it != this->mapUsers.end()) {
		IPv6Address network = networkstr;
		if(!network.isValid()) {
			throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid network parameter!"));
		}
		
		if(this->mapUsers[username].deleteNetwork(network)) {
			return this->flush();
		}
	}
	return false;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::AddAccount(const std::string username, std::string accountName, std::string permission) {
	std::map<std::string, CACLUser>::const_iterator it = this->mapUsers.find(username);
	if(it != this->mapUsers.end()) {
		uint8_t flags = ACL_ACCOUNT_NONE;
		if(permission == "ro") {
			flags = ACL_ACCOUNT_READONLY;
		}
		else if(permission == "rw") {
			flags = ACL_ACCOUNT_READWRITE;
		}
		else {
			throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid permission parameter!"));
		}
		if(this->mapUsers[username].addAccount(accountName, flags)) {
			return this->flush();
		}
	}
	return false;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::DeleteAccount(const std::string username, std::string accountName) {
	std::map<std::string, CACLUser>::const_iterator it = this->mapUsers.find(username);
	if(it != this->mapUsers.end()) {
		if(this->mapUsers[username].deleteAccount(accountName)) {
			return this->flush();
		}
	}
	return false;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUsers::flush() {
	CACLDB acldb;
    return acldb.Write(*this);
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value CACLUsers::Dump() {
	json_spirit::Array ret;
	
	ret.push_back(this->globalUser.Dump());
	
	typedef std::map<std::string, CACLUser> usermap;
	BOOST_FOREACH(usermap::value_type &user, this->mapUsers) {
		ret.push_back(user.second.Dump());
	}
	
	return ret;
}

