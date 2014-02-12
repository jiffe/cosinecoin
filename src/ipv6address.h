#ifndef IPV6ADDRESS_H
#define IPV6ADDRESS_H


#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdint.h>
#include "serialize.h"


class IPv6Address {
	private:
		uint64_t LOWER, UPPER;
		uint8_t bits;
		bool valid;
		
		
	public:
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		IPv6Address() : LOWER(0), UPPER(0), bits(128), valid(true) { }
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		template <typename S, typename T> IPv6Address(const S upper_rhs, const T lower_rhs, uint8_t bits = 128) : LOWER(lower_rhs), UPPER(upper_rhs), bits(bits), valid(true) {
			this->applyBits();
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		IPv6Address(const IPv6Address &rhs) : LOWER(rhs.LOWER), UPPER(rhs.UPPER), bits(rhs.bits), valid(true) {
			this->applyBits();
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		IPv6Address(std::string rhs) : LOWER(0), UPPER(0), bits(0) {
			this->valid = this->loadFromString(rhs);
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		template <typename T> IPv6Address operator=(T rhs) {
			UPPER = 0;
			LOWER = (uint64_t) rhs;
			return *this;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		IPv6Address operator=(IPv6Address rhs) {
			UPPER = rhs.UPPER;
			LOWER = rhs.LOWER;
			return *this;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		IPv6Address operator=(std::string rhs) {
			this->valid = loadFromString(rhs);
			return *this;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		IPv6Address operator&(IPv6Address rhs) {
			return IPv6Address(UPPER & rhs.UPPER, LOWER &  rhs.LOWER);
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		IPv6Address operator/(uint8_t bits) {
			return IPv6Address(UPPER, LOWER, bits);
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		bool operator==(IPv6Address rhs) {
			return (UPPER == rhs.UPPER && LOWER == rhs.LOWER && bits == rhs.bits);
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		void operator<<=(uint32_t val) {
			UPPER = (UPPER >> 1) | (LOWER & 0x800000000000000);
			LOWER >>= 1;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		void operator/=(uint8_t bits) {
			this->bits = bits;
			this->applyBits();
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		bool loadFromString(std::string rhs) {
			struct addrinfo hints, *res = NULL;
			memset(&hints, 0, sizeof(struct addrinfo));
			std::vector<std::string> tokens;
			
			split(tokens, rhs, boost::algorithm::is_any_of("/"));
			int ret = getaddrinfo(tokens[0].c_str(), NULL, &hints, &res);
			if(ret || !(res->ai_family == AF_INET || res->ai_family == AF_INET6)) {
				return false;
			}
			bits = 128;
			
			if(res->ai_family == AF_INET) {
				tokens[0] = "::ffff:" + tokens[0];
			}
			freeaddrinfo(res);
			inet_pton(AF_INET6, tokens[0].c_str(), this);
			this->endianSwap();
			if(this->getType() == AF_INET) {
				bits = 32;
			}
			
			// Subnet
			if(tokens.size() == 2) {
				bits = atoi(tokens[1].c_str());
				if(bits == 0 || (this->getType() == AF_INET && bits > 32) || (this->getType() == AF_INET && bits > 128)) {
					return false;
				}
				
				this->applyBits();
			}
			else if(tokens.size() != 1) {
				return false;
			}
			
			return true;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		int getBits() {
			return bits;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		void endianSwap() {
			uint64_t T;
			
			T = __builtin_bswap64(LOWER);
			LOWER = __builtin_bswap64(UPPER);
			UPPER = T;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		uint8_t getType() {
			return (UPPER == 0 && (LOWER & 0xffff000000000000) == 0x0000000000000000) ? AF_INET : AF_INET6;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		bool isValid() {
			return this->valid;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		void applyBits() {
			uint64_t bLOWER = 0xffffffffffffffff, bUPPER = 0xffffffffffffffff;
			
			uint8_t bbits = bits;
			if(this->getType() == AF_INET) bbits += 96;
			
			if(bbits <= 64) {
				bLOWER = 0;
				bUPPER <<= 64 - bbits;
			}
			else {
				bLOWER <<= 128 - bbits;
			}
			
			LOWER &= bLOWER;
			UPPER &= bUPPER;
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		std::string toString() {
			IPv6Address T = IPv6Address(*this);
			T.endianSwap();
			char buffer[45];
			
			if(this->getType() == AF_INET) {
				if(inet_ntop(AF_INET, ((unsigned char *)&T) + 12, buffer, INET_ADDRSTRLEN) == NULL) {
					return "";
				}
			}
			else {
				if(inet_ntop(AF_INET6, &T, buffer, INET6_ADDRSTRLEN) == NULL) {
					return "";
				}
			}
			
			strcat(buffer, "/");
			sprintf(buffer + strlen(buffer), "%u", bits);
			
			return std::string(buffer);
		}
		
		
		/***************************************************************************************************
		*
		*
		***************************************************************************************************/
		IMPLEMENT_SERIALIZE ({
			READWRITE(LOWER);
			READWRITE(UPPER);
			READWRITE(bits);
		})
		
		
};


#endif // IPV6ADDRESS_H