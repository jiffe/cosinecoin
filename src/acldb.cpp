#include <vector>
#include "acldb.h"


/***************************************************************************************************
*
*
***************************************************************************************************/
CACLDB::CACLDB() {
    pathACL = GetDataDir() / "acl.dat";
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLDB::Write(const CACLUsers &users) {
    // Generate random temporary filename
    unsigned short randv = 0;
    RAND_bytes((unsigned char *)&randv, sizeof(randv));
    std::string tmpfn = strprintf("acl.dat.%04x", randv);

    // serialize addresses, checksum data up to that point, then append csum
    CDataStream ssPeers(SER_DISK, CLIENT_VERSION);
    ssPeers << FLATDATA(pchMessageStart);
    ssPeers << users;
    uint256 hash = Hash(ssPeers.begin(), ssPeers.end());
    ssPeers << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = GetDataDir() / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout = CAutoFile(file, SER_DISK, CLIENT_VERSION);
    if(!fileout)
		return error("CACLUser::Write() : open failed");

    // Write and commit header, data
    try {
        fileout << ssPeers;
    }
    catch (std::exception &e) {
        return error("CACLUser::Write() : I/O error");
    }
	
    FileCommit(fileout);
    fileout.fclose();

    // replace existing acl.dat, if any, with new acl.dat.XXXX
    if (!RenameOver(pathTmp, pathACL))
        return error("CACLUser::Write() : Rename-into-place failed");
	
    return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool CACLDB::Read(CACLUsers &users) {
    // open input file, and associate with CAutoFile
	
    FILE *file = fopen(pathACL.string().c_str(), "rb");
    CAutoFile filein = CAutoFile(file, SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("CACLUser::Read() : open failed");

    // use file size to size memory buffer
    int fileSize = GetFilesize(filein);
    int dataSize = fileSize - sizeof(uint256);
    //Don't try to resize to a negative number if file is small
    if ( dataSize < 0 ) dataSize = 0;
    std::vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (std::exception &e) {
        return error("CACLUser::Read() 2 : I/O error or stream data corrupted");
    }
    filein.fclose();

    CDataStream ssPeers(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssPeers.begin(), ssPeers.end());
    if (hashIn != hashTmp)
        return error("CACLUser::Read() : checksum mismatch; data corrupted");

    unsigned char pchMsgTmp[4];
    try {
        // de-serialize file header (pchMessageStart magic number) and
        ssPeers >> FLATDATA(pchMsgTmp);

        // verify the network matches ours
        if(memcmp(pchMsgTmp, pchMessageStart, sizeof(pchMsgTmp)))
            return error("CACLUser::Read() : invalid network magic number");

        // de-serialize address data into one CACLUser object
        ssPeers >> users;
    }
    catch (std::exception &e) {
        return error("CACLUser::Read() : I/O error or stream data corrupted");
    }
	
    return true;
}

