#include <boost/foreach.hpp>
#include "acluser.h"
#include "aclperms.h"
#include "hash.h"


/***************************************************************************************************
*
*
***************************************************************************************************/
CACLUser::CACLUser() {
	this->username = "";
	this->password = "";
	this->perms = 0;
	this->enabled = false;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
CACLUser::CACLUser(const std::string username, const std::string password, uint64 perms, bool enabled) {
	this->username = username;
	this->password = password;
	this->perms = perms;
	this->enabled = enabled;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::auth(const std::string username, const std::string password, IPv6Address ip_address) {
	bool location_found = true;
	if(this->locations.size()) {
		location_found = false;
		json_spirit::Array locations;
		BOOST_FOREACH(IPv6Address &location, this->locations) {
			if((ip_address / location.getBits()) == location) {
				location_found = true;
				break;
			}
		}
	}
	return (location_found && username == this->username && Hash(password.begin(), password.end()).GetHex() == this->password);
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value CACLUser::Dump() {
	json_spirit::Object obj;
	
	obj.push_back(json_spirit::Pair("Username", this->username));
	obj.push_back(json_spirit::Pair("Permissions", dumpPermissionsByFlags(this->perms)));
	obj.push_back(json_spirit::Pair("Enabled", this->enabled));
	
	json_spirit::Array locations;
	BOOST_FOREACH(IPv6Address &location, this->locations) {
		locations.push_back(location.toString());
	}
	obj.push_back(json_spirit::Pair("Network Restrictions", locations));
	
	json_spirit::Object accounts;
	typedef std::map<std::string, uint8_t> acctmap;
	BOOST_FOREACH(acctmap::value_type &account, this->accounts) {
		accounts.push_back(json_spirit::Pair(account.first, (account.second == ACL_ACCOUNT_READWRITE) ? "read-write" : "read-only"));
	}
	obj.push_back(json_spirit::Pair("Account Access", accounts));
	
	return obj;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::enable() {
	this->enabled = true;
	return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::disable() {
	this->enabled = false;
	return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::grant(std::string perm) {
	uint64 flags = getPermissionFlagsByName(perm);
	this->perms |= flags;
	return (flags > 0);
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::revoke(std::string perm) {
	uint64 flags = getPermissionFlagsByName(perm);
	this->perms &= ~flags;
	return (flags > 0);
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::update(std::string password) {
	this->password = password;
	return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::addNetwork(IPv6Address network) {
	BOOST_FOREACH(IPv6Address &location, this->locations) {
		if(location == network) {
			return true;
		}
	}
	this->locations.push_back(network);
	return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::deleteNetwork(IPv6Address network) {
	for(unsigned int i = 0; i < this->locations.size(); i++) {
		if(this->locations[i] == network) {
			this->locations.erase(this->locations.begin() + i);
			break;
		}
	}
	return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::addAccount(std::string accountName, uint8_t flags) {
	this->accounts[accountName] = flags;
	return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::deleteAccount(std::string accountName) {
	this->accounts.erase(accountName);
	return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::isEnabled() {
	return this->enabled;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::check(uint64 permission) {
	return ((this->perms & permission) == permission);
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLUser::checkAccount(std::string accountName, uint8_t permission) {
	if(this->perms == ACL_GLOBAL) {
		return true;
	}
	std::map<std::string, uint8_t>::const_iterator it = this->accounts.find(accountName);
	if(it == this->accounts.end()) {
		return false;
	}
	if((this->accounts[accountName] & permission) != permission) {
		return false;
	}
	return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value CACLAccount::Dump() {
	json_spirit::Object obj;
	
	//obj.push_back(json_spirit::Pair("Username", this->username));
	//obj.push_back(json_spirit::Pair("Permissions", dumpPermissionsByFlags(this->perms)));
	//obj.push_back(json_spirit::Pair("Enabled", this->enabled));
	
	return obj;
}

