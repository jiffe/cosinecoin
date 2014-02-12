bin_PROGRAMS = cosinecoind

cosinecoind_LDFLAGS = -rdynamic -L/usr/local/lib -pthread
cosinecoind_CPPFLAGS = -I/usr/local/include/ -DBOOST_SPIRIT_THREADSAFE -D_FILE_OFFSET_BITS=64 -DUSE_UPNP=0 -DUSE_IPV6=1

cosinecoind_LDADD = 	-lboost_system \
						-lboost_filesystem \
						-lboost_program_options \
						-lboost_thread \
						-lleveldb \
						-lmemenv \
						-ldb_cxx \
						-lssl \
						-lcrypto \
						-lminiupnpc

cosinecoind_SOURCES = 	acldb.cpp \
						aclperms.cpp \
						acluser.cpp \
						aclusers.cpp \
						addrman.cpp \
						alert.cpp \
						bitcoinrpc.cpp \
						bloom.cpp \
						checkpoints.cpp \
						crypter.cpp \
						db.cpp \
						hash.cpp \
						init.cpp \
						irc.cpp \
						key.cpp \
						keystore.cpp \
						leveldb.cpp \
						main.cpp \
						net.cpp \
						netbase.cpp \
						noui.cpp \
						protocol.cpp \
						rpcacl.cpp \
						rpcblockchain.cpp \
						rpcdump.cpp \
						rpcmining.cpp \
						rpcnet.cpp \
						rpcrawtransaction.cpp \
						rpcwallet.cpp \
						script.cpp \
						scrypt.cpp \
						sync.cpp \
						txdb.cpp \
						util.cpp \
						version.cpp \
						wallet.cpp \
						walletdb.cpp
						