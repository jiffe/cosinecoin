#include <map>
#include "aclperms.h"


static const CACLPerm CACLPermissions[] =
{ //  name                      flags                    description
  //  ------------------------  -----------------------  --------------------------------------------------------------------------------------------
	{ "publicread",             ACL_PUBLICREAD,          "Permissions to read piblicly accessible information via RPC commands" },
	{ "peerread",               ACL_PEERREAD,            "Permissions to read this node's peer information" },
	{ "mineable",               ACL_MINEABLE,            "Permissions to mining RPC commands" },
	{ "auth",                   ACL_AUTH,                "Permissions to ACL RPC commands" },
	{ "global",                 ACL_GLOBAL,              "Permissions to all RPC commands" },
};


static std::map <std::string, const CACLPerm*> mapNames;
static std::map <uint64, const CACLPerm*> mapFlags;


/***************************************************************************************************
*
*
***************************************************************************************************/
void buildPermissionMappings() {
	unsigned int pidx;
	for(pidx = 0; pidx < (sizeof(CACLPermissions) / sizeof(CACLPermissions[0])); pidx++) {
		const CACLPerm *perm;
		perm = &CACLPermissions[pidx];
		printf("Mapping %s => %llu\n", perm->name.c_str(), perm->flags);
		mapNames[perm->name] = perm;
		mapFlags[perm->flags] = perm;
	}
}


/***************************************************************************************************
*
*
***************************************************************************************************/
json_spirit::Value dumpPermissionsByFlags(uint64 flags) {
	json_spirit::Array permlist;
	if(flags == ~uint64(0)) {
		permlist.push_back("global");
	}
	else {
		unsigned int pidx;
		for(pidx = 0; pidx < (sizeof(CACLPermissions) / sizeof(CACLPermissions[0])); pidx++) {
			if((flags & CACLPermissions[pidx].flags) == CACLPermissions[pidx].flags) {
				permlist.push_back(CACLPermissions[pidx].name);
			}
		}
	}
	return permlist;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
uint64 getPermissionFlagsByName(std::string name) {
	printf("Searching for %s\n",name.c_str());
	std::map<std::string, const CACLPerm*>::const_iterator it = mapNames.find(name);
	if(it == mapNames.end()) {
		return 0;
	}
	return mapNames[name]->flags;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
std::string getPermissionNameByFlags(uint64 flags) {
	std::map<uint64, const CACLPerm*>::const_iterator it = mapFlags.find(flags);
	if(it == mapFlags.end()) {
		return "";
	}
	return mapFlags[flags]->name;
}

