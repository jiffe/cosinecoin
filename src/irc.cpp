// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2012 Litecoin Developers
// Copyright (c) 2014 CosineCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netdb.h>
#include "irc.h"
#include "net.h"
#include "strlcpy.h"
#include "base58.h"

using namespace std;
using namespace boost;

int nGotIRCAddresses = 0;

void ThreadIRCSeed2(void* parg);
extern volatile bool fRequestShutdown;



#pragma pack(push, 1)
/***************************************************************************************************
*
*
***************************************************************************************************/
struct ircaddr {
    struct in_addr ip;
    short port;
};
#pragma pack(pop)


/***************************************************************************************************
*
*
***************************************************************************************************/
string EncodeAddress(const CService& addr) {
    struct ircaddr tmp;
    if (addr.GetInAddr(&tmp.ip))
    {
        tmp.port = htons(addr.GetPort());

        vector<unsigned char> vch(UBEGIN(tmp), UEND(tmp));
        return string("u") + EncodeBase58Check(vch);
    }
    return "";
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool DecodeAddress(string str, CService& addr) {
    vector<unsigned char> vch;
    if (!DecodeBase58Check(str.substr(1), vch))
        return false;

    struct ircaddr tmp;
    if (vch.size() != sizeof(tmp))
        return false;
    memcpy(&tmp, &vch[0], sizeof(tmp));

    addr = CService(tmp.ip, ntohs(tmp.port));
    return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
static bool Send(SOCKET hSocket, const char* pszSend) {
    if (strstr(pszSend, "PONG") != pszSend)
        printf("IRC SENDING: %s\n", pszSend);
    const char* psz = pszSend;
    const char* pszEnd = psz + strlen(psz);
    while (psz < pszEnd)
    {
        int ret = send(hSocket, psz, pszEnd - psz, MSG_NOSIGNAL);
        if (ret < 0)
            return false;
        psz += ret;
    }
    return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool RecvLineIRC(SOCKET hSocket, string& strLine) {
    loop
    {
        bool fRet = RecvLine(hSocket, strLine);
        if (fRet)
        {
            if (fRequestShutdown)
                return false;
            vector<string> vWords;
            ParseString(strLine, ' ', vWords);
            if (vWords.size() >= 1 && vWords[0] == "PING")
            {
                strLine[1] = 'O';
                strLine += '\r';
                Send(hSocket, strLine.c_str());
                continue;
            }
        }
        return fRet;
    }
}


/***************************************************************************************************
*
*
***************************************************************************************************/
int RecvUntil(SOCKET hSocket, const char* psz1, const char* psz2=NULL, const char* psz3=NULL, const char* psz4=NULL) {
    loop
    {
        string strLine;
        strLine.reserve(10000);
        if (!RecvLineIRC(hSocket, strLine))
            return 0;
        printf("IRC %s\n", strLine.c_str());
        if (psz1 && strLine.find(psz1) != string::npos)
            return 1;
        if (psz2 && strLine.find(psz2) != string::npos)
            return 2;
        if (psz3 && strLine.find(psz3) != string::npos)
            return 3;
        if (psz4 && strLine.find(psz4) != string::npos)
            return 4;
    }
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool Wait(int nSeconds) {
    if (fRequestShutdown)
        return false;
    printf("IRC waiting %d seconds to reconnect\n", nSeconds);
    for (int i = 0; i < nSeconds; i++)
    {
        if (fRequestShutdown)
            return false;
        usleep(1000000);
    }
    return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool RecvCodeLine(SOCKET hSocket, const char* psz1, string& strRet) {
    strRet.clear();
    loop
    {
        string strLine;
        if (!RecvLineIRC(hSocket, strLine))
            return false;

        vector<string> vWords;
        ParseString(strLine, ' ', vWords);
        if (vWords.size() < 2)
            continue;

        if (vWords[1] == psz1)
        {
            printf("IRC %s\n", strLine.c_str());
            strRet = strLine;
            return true;
        }
    }
}


/***************************************************************************************************
*
*
***************************************************************************************************/
bool GetIPFromIRC(SOCKET hSocket, string strMyName, CNetAddr& ipRet) {
    Send(hSocket, strprintf("USERHOST %s\r", strMyName.c_str()).c_str());

    string strLine;
    if (!RecvCodeLine(hSocket, "302", strLine))
        return false;

    vector<string> vWords;
    ParseString(strLine, ' ', vWords);
    if (vWords.size() < 4)
        return false;

    string str = vWords[3];
    if (str.rfind("@") == string::npos)
        return false;
    string strHost = str.substr(str.rfind("@")+1);

    // Hybrid IRC used by lfnet always returns IP when you userhost yourself,
    // but in case another IRC is ever used this should work.
    printf("GetIPFromIRC() got userhost %s\n", strHost.c_str());
    CNetAddr addr(strHost, true);
    if (!addr.IsValid())
        return false;
    ipRet = addr;

    return true;
}


/***************************************************************************************************
*
*
***************************************************************************************************/
void ThreadIRCSeed() {
    //IMPLEMENT_RANDOMIZE_STACK(ThreadIRCSeed(parg));

    // Make this thread recognisable as the IRC seeding thread
    RenameThread("bitcoin-ircseed");

    try
    {
        ThreadIRCSeed2(NULL);
    }
    catch (std::exception& e) {
        PrintExceptionContinue(&e, "ThreadIRCSeed()");
    } catch (...) {
        PrintExceptionContinue(NULL, "ThreadIRCSeed()");
    }
    printf("ThreadIRCSeed exited\n");
}


/***************************************************************************************************
*
*
***************************************************************************************************/
void ThreadIRCSeed2(void* parg) {
    /* Dont advertise on IRC if we don't allow incoming connections */
    if (mapArgs.count("-connect") || fNoListen)
        return;

    if (!GetBoolArg("-irc", false))
        return;

    printf("ThreadIRCSeed started\n");
    int nErrorWait = 10;
    int nRetryWait = 10;
	
	struct hostent entries;
	struct hostent *result;
	int index = -1;
	int len = 0;
	int err = 0;
	int rc = 0;
	char *buf = NULL;

    while(!fRequestShutdown) {
		if(index < 0) {
			while((rc = gethostbyname_r("irc.lfnet.org", &entries, buf, len, &result, &err)) == ERANGE) {
				/* expand buf */
				len *= 2;
				buf = (char *)realloc(buf, len);
				if(NULL == buf) {
					printf("Memory allocation error during IRC DNS resolution\n");
					Wait(10);
					continue;
				}
			}
			if(0 != rc || NULL == result) {
				printf("Failed to resolve IRC server irc.lfnet.org\n");
				Wait(10);
				continue;
			}
		}
		
		if(++index >= entries.h_length) {
			index = -1;
			printf("Exhausted all irc IP entries, starting over in 10 seconds\n");
			Wait(10);
			continue;
		}
		
	
        //CService addrConnect("92.243.23.21", 6667); // irc.lfnet.org
		struct in_addr *ipptr = (struct in_addr *)entries.h_addr_list[index];
		printf("Trying IRC server %s\n", inet_ntoa(*ipptr));
		CService addrConnect(inet_ntoa(*ipptr), 6667);

        //CService addrIRC("irc.lfnet.org", 6667, true);
        //if(addrIRC.IsValid()) {
		//	printf("Set IRC server irc.lfnet.org\n");
        //    addrConnect = addrIRC;
		//}

        SOCKET hSocket;
        if (!ConnectSocket(addrConnect, hSocket))
        {
            printf("IRC connect failed\n");
            nErrorWait = nErrorWait * 11 / 10;
            if (Wait(nErrorWait += 60))
                continue;
            else
                return;
        }

        if (!RecvUntil(hSocket, "Found your hostname", "using your IP address instead", "Couldn't look up your hostname", "ignoring hostname"))
        {
            closesocket(hSocket);
            hSocket = INVALID_SOCKET;
            nErrorWait = nErrorWait * 11 / 10;
            if (Wait(nErrorWait += 60))
                continue;
            else
                return;
        }

        CNetAddr addrIPv4("1.2.3.4"); // arbitrary IPv4 address to make GetLocal prefer IPv4 addresses
        CService addrLocal;
        string strMyName;
        if (GetLocal(addrLocal, &addrIPv4))
            strMyName = EncodeAddress(GetLocalAddress(&addrConnect));
        if (strMyName == "")
            strMyName = strprintf("x%u", (unsigned int)GetRand(1000000000));

        Send(hSocket, strprintf("NICK %s\r", strMyName.c_str()).c_str());
        Send(hSocket, strprintf("USER %s 8 * : %s\r", strMyName.c_str(), strMyName.c_str()).c_str());

        int nRet = RecvUntil(hSocket, " 004 ", " 433 ");
        if (nRet != 1)
        {
            closesocket(hSocket);
            hSocket = INVALID_SOCKET;
            if (nRet == 2)
            {
                printf("IRC name already in use\n");
                Wait(10);
                continue;
            }
            nErrorWait = nErrorWait * 11 / 10;
            if (Wait(nErrorWait += 60))
                continue;
            else
                return;
        }
        usleep(500000);

        // Get our external IP from the IRC server and re-nick before joining the channel
        CNetAddr addrFromIRC;
        if (GetIPFromIRC(hSocket, strMyName, addrFromIRC))
        {
            printf("GetIPFromIRC() returned %s\n", addrFromIRC.ToString().c_str());
            if (addrFromIRC.IsRoutable())
            {
                // IRC lets you to re-nick
                AddLocal(addrFromIRC, LOCAL_IRC);
                strMyName = EncodeAddress(GetLocalAddress(&addrConnect));
                Send(hSocket, strprintf("NICK %s\r", strMyName.c_str()).c_str());
            }
        }
        
        if (fTestNet) {
            Send(hSocket, "JOIN #cosinecoinTEST1\r");
            Send(hSocket, "WHO #cosinecoinTEST2\r");
        } else {
            // randomly join #cosinecoin00-#cosinecoin99
            int channel_number = GetRandInt(100);
            channel_number = 0; // Litecoin: for now, just use one channel
            Send(hSocket, strprintf("JOIN #cosinecoin%02d\r", channel_number).c_str());
            Send(hSocket, strprintf("WHO #cosinecoin%02d\r", channel_number).c_str());
        }

        int64 nStart = GetTime();
        string strLine;
        strLine.reserve(10000);
        while (!fRequestShutdown && RecvLineIRC(hSocket, strLine))
        {
            if (strLine.empty() || strLine.size() > 900 || strLine[0] != ':')
                continue;

            vector<string> vWords;
            ParseString(strLine, ' ', vWords);
            if (vWords.size() < 2)
                continue;

            char pszName[10000];
            pszName[0] = '\0';

            if (vWords[1] == "352" && vWords.size() >= 8)
            {
                // index 7 is limited to 16 characters
                // could get full length name at index 10, but would be different from join messages
                strlcpy(pszName, vWords[7].c_str(), sizeof(pszName));
                printf("IRC got who\n");
            }

            if (vWords[1] == "JOIN" && vWords[0].size() > 1)
            {
                // :username!username@50000007.F000000B.90000002.IP JOIN :#channelname
                strlcpy(pszName, vWords[0].c_str() + 1, sizeof(pszName));
                if (strchr(pszName, '!'))
                    *strchr(pszName, '!') = '\0';
                printf("IRC got join\n");
            }

            if (pszName[0] == 'u')
            {
                CAddress addr;
                if (DecodeAddress(pszName, addr))
                {
                    addr.nTime = GetAdjustedTime();
                    if (addrman.Add(addr, addrConnect, 51 * 60))
                        printf("IRC got new address: %s\n", addr.ToString().c_str());
                    nGotIRCAddresses++;
                }
                else
                {
                    printf("IRC decode failed\n");
                }
            }
        }
        closesocket(hSocket);
        hSocket = INVALID_SOCKET;

        if (GetTime() - nStart > 20 * 60)
        {
            nErrorWait /= 3;
            nRetryWait /= 3;
        }

        nRetryWait = nRetryWait * 11 / 10;
        if (!Wait(nRetryWait += 60))
            return;
    }
	
	if(buf)
		free(buf);
}


/***************************************************************************************************
*
*
***************************************************************************************************/
#ifdef TEST
int main(int argc, char *argv[])
{
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2,2), &wsadata) != NO_ERROR)
    {
        printf("Error at WSAStartup()\n");
        return false;
    }

    ThreadIRCSeed(NULL);

    WSACleanup();
    return 0;
}
#endif

