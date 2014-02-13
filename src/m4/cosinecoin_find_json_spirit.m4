AC_DEFUN([COSINECOIN_FIND_JSON_SPIRIT],[
	AC_MSG_CHECKING([for libjson_spirit headers])
	
	for _header in json_spirit_writer_options.h json_spirit_reader_template.h json_spirit_writer_template.h json_spirit_utils.h; do
		AC_TRY_COMPILE([
		  #include <${_header}>
		],[
		  
		],[
		  continue
		],[
		  AC_MSG_RESULT([no])
		  AC_MSG_ERROR(missing header ${_header})
		])
	done
	AC_MSG_RESULT([yes])
])
