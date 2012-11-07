#include <tcl.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <limits.h>

#define PHPAPI
#define ZEND_API
#define TSRMLS_DC
#define TSRMLS_CC
#define TSRMLS_FETCH()

#define zval	char
#define Z_STRLEN_P(str)	strlen(str)
#define Z_STRLEN_PP(str)	strlen(str)

#define Z_STRVAL_P(zval_p)  zval_p
#define Z_STRVAL_PP(zval_p)  zval_p

#define estrdup(s)          strdup(s)
#define php_memnstr         zend_memnstr
#define estrndup(s, length) zend_strndup((s), (length))

#define STR_EMPTY_ALLOC() estrndup("", sizeof("")-1)

#define TCL_FUNCTION(name)            static int name( ClientData data, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[] )
#define PHP_FUNCTION(name)            TCL_FUNCTION(name)

#define INTERNAL_FUNCTION_PARAMETERS  ClientData data, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]
#define INTERNAL_FUNCTION_PARAM_PASSTHRU	data, interp, objc, objv

#define ZVAL_DOUBLE(z, d)	sprintf("%ld",z)
#define ZVAL_LONG(z, d)	sprintf("%ld",z)

#define zend_isinf(a) isinf(a)
#define zend_isnan(a) isnan(a)

#define emalloc(size)       malloc(size)
#define efree(ptr)          free(ptr)
#define _emalloc(size)      malloc(size)
#define _efree(ptr)         free(ptr)

#define ecalloc(nmemb, size)                       calloc((nmemb), (size))
#define safe_emalloc(nmemb, size, offset)          malloc((nmemb) * (size) + (offset))

#define BEGIN_EXTERN_C()
#define END_EXTERN_C()

#define ZEND_ATTRIBUTE_FORMAT(type, idx, first)	
#define PHP_ATTRIBUTE_FORMAT(type, idx, first)

#define E_ERROR             (1<<0L)
#define E_WARNING           (1<<1L)
#define E_PARSE             (1<<2L)
#define E_NOTICE            (1<<3L)
#define E_CORE_ERROR        (1<<4L)
#define E_CORE_WARNING      (1<<5L)
#define E_COMPILE_ERROR     (1<<6L)
#define E_COMPILE_WARNING   (1<<7L)
#define E_USER_ERROR        (1<<8L)
#define E_USER_WARNING      (1<<9L)
#define E_USER_NOTICE       (1<<10L)
#define E_STRICT            (1<<11L)

#define E_ALL (E_ERROR | E_WARNING | E_PARSE | E_NOTICE | E_CORE_ERROR | E_CORE_WARNING | E_COMPILE_ERROR | E_COMPILE_WARNING | E_USER_ERROR | E_USER_WARNING | E_USER_NOTICE)
#define E_CORE (E_CORE_ERROR | E_CORE_WARNING)

//#define INT_MAX 2147483647

#define IS_NULL     0
#define IS_LONG     1
#define IS_DOUBLE   2
#define IS_BOOL     3
#define IS_ARRAY    4
#define IS_OBJECT   5
#define IS_STRING   6
#define IS_RESOURCE 7
#define IS_CONSTANT 8
#define IS_CONSTANT_ARRAY   9

#ifndef LONG_MAX
#define LONG_MAX 2147483647L
#endif

#ifndef LONG_MIN
#define LONG_MIN (- LONG_MAX - 1)
#endif

#undef SUCCESS
#undef FAILURE
#define SUCCESS 0
#define FAILURE -1              /* this MUST stay a negative number, or it may affect functions! */

#undef MIN
#undef MAX
#define MAX(a, b)  (((a)>(b))?(a):(b))
#define MIN(a, b)  (((a)<(b))?(a):(b))
#define ZEND_STRL(str)      (str), (sizeof(str)-1)
#define ZEND_STRS(str)      (str), (sizeof(str))
#define ZEND_NORMALIZE_BOOL(n) 	((n) ? (((n)>0) ? 1 : -1) : 0)
#define ZEND_TRUTH(x)       	((x) ? 1 : 0)
#define ZEND_LOG_XOR(a, b)      (ZEND_TRUTH(a) ^ ZEND_TRUTH(b))
#define HEX2BIN(a,n)			hex2bin(a,n);
#define BIN2HEX(o,on,nn)		php_bin2hex(o,on,nn);

static char hexconvtab[] = "0123456789abcdef";

long php_rand();
char *zend_strndup(const char *s, uint length);
char *zend_memnstr(char *haystack, char *needle, int needle_len, char *end);
char x2b(char c);
char *hex2bin(char *hexstring, int maxbuf);
char *php_bin2hex(const unsigned char *old, const size_t oldlen, size_t *newlen);
