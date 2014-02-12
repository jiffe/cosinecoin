// Copyright (c) 2014 CosineCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ACLPERMS_H
#define ACLPERMS_H


#include <string>
#include "util.h"

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"


#define ACL_PUBLICREAD    ( uint64(1) << 0  )
#define ACL_PEERREAD      ( uint64(1) << 1  )
#define ACL_MINEABLE      ( uint64(1) << 2  )
#define ACL_AUTH          ( uint64(1) << 62 )
#define ACL_GLOBAL        ( ~uint64(0) )

#define ACL_ACCOUNT_NONE  0x0
#define ACL_ACCOUNT_READONLY  0x1
#define ACL_ACCOUNT_READWRITE 0x3


struct CACLPerm {
	std::string name;
    uint64 flags;
    std::string description;
};


void buildPermissionMappings();
json_spirit::Value dumpPermissionsByFlags(uint64 flags);
uint64 getPermissionFlagsByName(std::string name);
std::string getPermissionNameByFlags(uint64 flags);


#endif // ACLPERMS_H
