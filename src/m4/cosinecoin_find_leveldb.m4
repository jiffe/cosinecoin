AC_DEFUN([COSINECOIN_FIND_LEVELDB],[
	AC_MSG_CHECKING([for LevelDB headers])
	
	for _header in db.h env.h cache.h filter_policy.h write_batch.h options.h helpers/memenv.h; do
		AC_TRY_COMPILE([
			#include <leveldb/${_header}>
		],[
		  
		],[
			continue
		],[
			AC_MSG_RESULT([no])
			AC_MSG_ERROR(missing header leveldb/${_header})
		])
	done
	
	#for searchlib in leveldb memenv; do
	#	AC_CHECK_LIB([$searchlib],[main],[
	#		continue
	#	],[
	#		AC_MSG_RESULT([no])
	#		AC_MSG_ERROR(missing libary ${_lib})
	#	])
	#done
])