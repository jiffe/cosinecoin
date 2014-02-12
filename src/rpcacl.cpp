// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h" // for pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"

#include <boost/lexical_cast.hpp>

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value acldump(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 0)
        throw std::runtime_error("acldump\nDump the contents of the ACL database");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.Dump();
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value aclcreate(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 2)
        throw std::runtime_error("aclcreate <username> <password>\nCreate a new RPC user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.Create(params[0].get_str(), params[1].get_str(), 0, 0);
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value aclremove(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 1)
        throw std::runtime_error("aclremove <username>\nRemove an existing RPC user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.Remove(params[0].get_str());
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value aclenable(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 1)
        throw std::runtime_error("aclenable <username>\nEnable an ACL user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.Enable(params[0].get_str());
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value acldisable(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 1)
        throw std::runtime_error("acldisable <username>\nDisable an ACL user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.Disable(params[0].get_str());
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value aclgrant(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 2)
        throw std::runtime_error("aclgrant <username> <permission>\nGrant the given permission to the given user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.Grant(params[0].get_str(), params[1].get_str());
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value aclrevoke(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 2)
        throw std::runtime_error("aclrevoke <username> <permission>\nRevoke the given permission from the given user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.Revoke(params[0].get_str(), params[1].get_str());
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value aclpassword(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 2)
        throw std::runtime_error("aclpassword <username> <password>\nUpdate the password for the given user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.Update(params[0].get_str(), params[1].get_str());
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value acladdnet(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 2)
        throw std::runtime_error("acladdnet <username> <network>[/netmask]\nAdd the given network[/netmask] restriction to the given user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.AddNetwork(params[0].get_str(), params[1].get_str());
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value acldelnet(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 2)
        throw std::runtime_error("acldelnet <username> <network>[/netmask]\nRemove the given network[/netmask] restriction from the given user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.DeleteNetwork(params[0].get_str(), params[1].get_str());
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value acladdaccount(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 3)
        throw std::runtime_error("acladdaccount <username> <account> <ro/rw>\nAdd an account with the given permissions to the given user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.AddAccount(params[0].get_str(), params[1].get_str(), params[2].get_str());
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value acldelaccount(const json_spirit::Array& params, bool fHelp, CACLUser &user) {
	if (fHelp || params.size() != 2)
        throw std::runtime_error("acldelaccount <username> <account>\nRemove the given account from the given user");
	
	if(!user.check(ACL_AUTH)) {
		throw JSONRPCError(RPC_PERMISSION_DENIED, "Permission denied!");
	}
	
	return aclusers.DeleteAccount(params[0].get_str(), params[1].get_str());
}


