/*
    php tcl package
    2008.12.04 created by dancal
*/

#include <tcl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <ctype.h>

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <dirent.h>

#include <fcntl.h>
#include "mcrypt.h"

#include "tcl_mcrypt.h"
#include "ext/tcl_compat.h"
#include "ext/php_compat.h"
#include "ext/php_smart_str.h"

#define MCRYPT_ENCRYPT 0
#define MCRYPT_DECRYPT 1

char *algorithms_dir = NULL;
static Tcl_HashTable bars;

//
char *getcipher( char *str ) {
//{{{
	if ( strcmp("MCRYPT_3DES",str) == 0 ) { return "tripledes"; } 
	else if ( strcmp("MCRYPT_ARCFOUR_IV",str) == 0 ) { return "arcfour-iv"; }
	else if ( strcmp("MCRYPT_ARCFOUR",str) == 0 ) { return "arcfour"; }
	else if ( strcmp("MCRYPT_BLOWFISH",str) == 0 ) { return "blowfish"; }
	else if ( strcmp("MCRYPT_BLOWFISH_COMPAT",str) == 0 ) { return "blowfish-compat"; }
	else if ( strcmp("MCRYPT_CAST_128",str) == 0 ) { return "cast-128"; }
	else if ( strcmp("MCRYPT_CAST_256",str) == 0 ) { return "cast-256"; }
	else if ( strcmp("MCRYPT_CRYPT",str) == 0 ) { return "crypt"; }
	else if ( strcmp("MCRYPT_DES",str) == 0 ) { return "des"; }
	else if ( strcmp("MCRYPT_ENIGNA",str) == 0 ) { return "crypt"; }
	else if ( strcmp("MCRYPT_GOST",str) == 0 ) { return "gost"; }
	else if ( strcmp("MCRYPT_LOKI97",str) == 0 ) { return "loki97"; }
	else if ( strcmp("MCRYPT_PANAMA",str) == 0 ) { return "panama"; }
	else if ( strcmp("MCRYPT_RC2",str) == 0 ) { return "rc2"; }
	else if ( strcmp("MCRYPT_RIJNDAEL_128",str) == 0 ) { return "rijndael-128"; }
	else if ( strcmp("MCRYPT_RIJNDAEL_192",str) == 0 ) { return "rijndael-192"; }
	else if ( strcmp("MCRYPT_RIJNDAEL_256",str) == 0 ) { return "rijndael-256"; }
	else if ( strcmp("MCRYPT_SAFER64",str) == 0 ) { return "safer-sk64"; }
	else if ( strcmp("MCRYPT_SAFER128",str) == 0 ) { return "safer-sk128"; }
	else if ( strcmp("MCRYPT_SAFERPLUS",str) == 0 ) { return "saferplus"; }
	else if ( strcmp("MCRYPT_SERPENT",str) == 0 ) { return "serpent"; }
	else if ( strcmp("MCRYPT_THREEWAY",str) == 0 ) { return "threeway"; }
	else if ( strcmp("MCRYPT_TRIPLEDES",str) == 0 ) { return "tripledes"; }
	else if ( strcmp("MCRYPT_TWOFISH",str) == 0 ) { return "twofish"; }
	else if ( strcmp("MCRYPT_WAKE",str) == 0 ) { return "wake"; }
	else if ( strcmp("MCRYPT_XTEA",str) == 0 ) { return "xtea"; }
	else if ( strcmp("MCRYPT_IDEA",str) == 0 ) { return "idea"; }
	else if ( strcmp("MCRYPT_MARS",str) == 0 ) { return "mars"; }
	else if ( strcmp("MCRYPT_RC6",str) == 0 ) { return "rc6"; }
	else if ( strcmp("MCRYPT_SKIPJACK",str) == 0 ) { return "skipjack"; }
	//mode
	else if ( strcmp("MCRYPT_MODE_CBC",str) == 0 ) { return "cbc"; }
	else if ( strcmp("MCRYPT_MODE_CFB",str) == 0 ) { return "cfb"; }
	else if ( strcmp("MCRYPT_MODE_ECB",str) == 0 ) { return "ecb"; }
	else if ( strcmp("MCRYPT_MODE_NOFB",str) == 0 ) { return "nofb"; }
	else if ( strcmp("MCRYPT_MODE_OFB",str) == 0 ) { return "ofb"; }
	else if ( strcmp("MCRYPT_MODE_STREAM",str) == 0 ) { return "stream"; }

	return NULL;
//}}}
}

//
unsigned char *php_mcrypt_do_crypt(char* cipher, char *key,char *data,char *mode,char *iv,int argc,int dencrypt) {
//{{{
    char *cipher_dir_string = NULL;
    char *module_dir_string = NULL;
    int block_size, max_key_length, use_key_length, i, count, iv_size;
    unsigned long int data_size;
    int *key_length_sizes;
    char *key_s = NULL, *iv_s;
    char *data_s;
    MCRYPT td;

    td = mcrypt_module_open(cipher, cipher_dir_string, mode, module_dir_string);
    if (td == MCRYPT_FAILED) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, MCRYPT_OPEN_MODULE_FAILED);
        //RETURN_FALSE;
		return NULL;
    }
    /* Checking for key-length */
    max_key_length = mcrypt_enc_get_key_size(td);
    if (Z_STRLEN_P(key) > max_key_length) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Size of key is too large for this algorithm");
		return NULL;
    }
    key_length_sizes = mcrypt_enc_get_supported_key_sizes(td, &count);
    if (count == 0 && key_length_sizes == NULL) { /* all lengths 1 - k_l_s = OK */
        use_key_length = Z_STRLEN_P(key);
        key_s = emalloc(use_key_length);
        memset(key_s, 0, use_key_length);
        memcpy(key_s, Z_STRVAL_P(key), use_key_length);
    } else if (count == 1) {  /* only m_k_l = OK */
        key_s = emalloc(key_length_sizes[0]);
        memset(key_s, 0, key_length_sizes[0]);
        memcpy(key_s, Z_STRVAL_P(key), MIN(Z_STRLEN_P(key), key_length_sizes[0]));
        use_key_length = key_length_sizes[0];
    } else { /* dertermine smallest supported key > length of requested key */
        use_key_length = max_key_length; /* start with max key length */
        for (i = 0; i < count; i++) {
            if (key_length_sizes[i] >= Z_STRLEN_P(key) && key_length_sizes[i] < use_key_length) {
                use_key_length = key_length_sizes[i];
            }
        }
        key_s = emalloc(use_key_length);
        memset(key_s, 0, use_key_length);
        memcpy(key_s, Z_STRVAL_P(key), MIN(Z_STRLEN_P(key), use_key_length));
    }
    mcrypt_free (key_length_sizes);

    /* Check IV */
    iv_s = NULL;
    iv_size = mcrypt_enc_get_iv_size (td);

    /* IV is required */
    if (mcrypt_enc_mode_has_iv(td) == 1) {
        if (argc == 6) {
            if (iv_size != Z_STRLEN_P(iv)) {
                //php_error_docref(NULL TSRMLS_CC, E_WARNING, MCRYPT_IV_WRONG_SIZE);
            } else {
                iv_s = emalloc(iv_size + 1);
                memcpy(iv_s, Z_STRVAL_P(iv), iv_size);
            }
        } else if (argc == 5) {
            //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Attempt to use an empty IV, which is NOT recommend");
            iv_s = emalloc(iv_size + 1);
            memset(iv_s, 0, iv_size + 1);
        }
    }

    /* Check blocksize */
    if (mcrypt_enc_is_block_mode(td) == 1) { /* It's a block algorithm */
        block_size = mcrypt_enc_get_block_size(td);
        data_size = (((Z_STRLEN_P(data) - 1) / block_size) + 1) * block_size;
        data_s = emalloc(data_size);
        memset(data_s, 0, data_size);
        memcpy(data_s, Z_STRVAL_P(data), Z_STRLEN_P(data));
    } else { /* It's not a block algorithm */
        data_size = Z_STRLEN_P(data);
        data_s = emalloc(data_size);
        memset(data_s, 0, data_size);
        memcpy(data_s, Z_STRVAL_P(data), Z_STRLEN_P(data));
    }

    if (mcrypt_generic_init(td, key_s, use_key_length, iv_s) < 0) {
        //php_error_docref(NULL TSRMLS_CC, E_RECOVERABLE_ERROR, "Mcrypt initialisation failed");
        //RETURN_FALSE;
		return NULL;
    }
    if (dencrypt == MCRYPT_ENCRYPT) {
        mcrypt_generic(td, data_s, data_size);
    } else {
        mdecrypt_generic(td, data_s, data_size);
    }

    /* freeing vars */
    mcrypt_generic_end(td);

    if (key_s != NULL) {
        efree (key_s);
    }
    if (iv_s != NULL) {
        efree (iv_s);
    }
   //RETVAL_STRINGL(data_s, data_size, 1);
    //efree (data_s);

	return data_s;
//}}}
}

//
TCL_FUNCTION(tcl_mcrypt) {
//{{{
    char **modules;
    char mcrypt_api_no[16];
	char sTemp[4096];

    int i, count;
	int nRc;
    smart_str tmp1 = {0};
    smart_str tmp2 = {0};
    Tcl_Obj *tobjList =NULL;
    Tcl_Obj *tobjNew = NULL;

    modules = mcrypt_list_algorithms(algorithms_dir, &count);
    if (count == 0) {
        smart_str_appends(&tmp1, "none");
    }
    for (i = 0; i < count; i++) {
        smart_str_appends(&tmp1, modules[i]);
        smart_str_appendc(&tmp1, ' ');
    }
    smart_str_0(&tmp1);
    mcrypt_free_p(modules, count);

    modules = mcrypt_list_modes(modes_dir, &count);
    if (count == 0) {
        smart_str_appends(&tmp2, "none");
    }
    for (i = 0; i < count; i++) {
        smart_str_appends(&tmp2, modules[i]);
        smart_str_appendc(&tmp2, ' ');
    }
    smart_str_0 (&tmp2);
    mcrypt_free_p (modules, count);

    snprintf (mcrypt_api_no, 16, "%d", MCRYPT_API_VERSION);

	tobjList = Tcl_NewListObj( 0, NULL );

	memset(sTemp,0x00,sizeof(sTemp));
	sprintf(sTemp,"Version : %s",LIBMCRYPT_VERSION);
    tobjNew = Tcl_NewStringObj(sTemp,sizeof(sTemp));
    nRc = Tcl_ListObjAppendElement( interp, tobjList, tobjNew );

	memset(sTemp,0x00,sizeof(sTemp));
	sprintf(sTemp,"Api No : %s",mcrypt_api_no);
    tobjNew = Tcl_NewStringObj(sTemp,sizeof(sTemp));
    nRc = Tcl_ListObjAppendElement( interp, tobjList, tobjNew );

	memset(sTemp,0x00,sizeof(sTemp));
	sprintf(sTemp,"Supported ciphers : %s",tmp1.c);
    tobjNew = Tcl_NewStringObj(sTemp,sizeof(sTemp));
    nRc = Tcl_ListObjAppendElement( interp, tobjList, tobjNew );

	memset(sTemp,0x00,sizeof(sTemp));
	sprintf(sTemp,"Supported ciphers : %s",tmp2.c);
    tobjNew = Tcl_NewStringObj(sTemp,sizeof(sTemp));
    nRc = Tcl_ListObjAppendElement( interp, tobjList, tobjNew );

    Tcl_SetObjResult( interp, tobjList );

    smart_str_free(&tmp1);
    smart_str_free(&tmp2);

	return TCL_OK;
//}}}
}

TCL_FUNCTION(tcl_mcrypt_list_algorithms) {
//{{{
    int nRc;

    char **modules;
    char *lib_dir = NULL;
    int   lib_dir_len;
    int   i, count;

    Tcl_Obj *tobjList =NULL;
    Tcl_Obj *tobjNew = NULL;
//    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s",&lib_dir, &lib_dir_len) == FAILURE) {
//        return;
//    }

    modules = mcrypt_list_algorithms(lib_dir, &count);
    if (count == 0) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, "No algorithms found in module dir");
		ERRORTCL("No algorithms found in module dir");
		return TCL_ERROR;
    }

	tobjList = Tcl_NewListObj( 0, NULL );
    for (i = 0; i < count; i++) {
        //add_index_string(return_value, i, modules[i], 1);
    	tobjNew = Tcl_NewStringObj(modules[i],strlen(modules[i]));
	    nRc = Tcl_ListObjAppendElement( interp, tobjList, tobjNew );
    }
    mcrypt_free_p(modules, count);

    Tcl_SetObjResult( interp, tobjList );

	return TCL_OK;
//}}}
}

TCL_FUNCTION(tcl_mcrypt_list_modes) {
//{{{
    char **modules;
    char *lib_dir = NULL;
    int lib_dir_len;
    int i, count;
	int nRc;
    Tcl_Obj *tobjList =NULL;
    Tcl_Obj *tobjNew = NULL;

    modules = mcrypt_list_modes(lib_dir, &count);
    if (count == 0) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, "No modes found in module dir");
		ERRORTCL("No modes found in module dir");
    }

	tobjList = Tcl_NewListObj( 0, NULL );
    for (i = 0; i < count; i++) {
    	tobjNew = Tcl_NewStringObj(modules[i],strlen(modules[i]));
	    nRc = Tcl_ListObjAppendElement( interp, tobjList, tobjNew );
    }
    mcrypt_free_p(modules, count);

    Tcl_SetObjResult( interp, tobjList );

	return TCL_OK;
//}}}
}

TCL_FUNCTION(tcl_mcrypt_get_key_size) {
//{{{
    char *cipher;
    char *module;
    int   cipher_len, module_len;
    char *cipher_dir_string = NULL;
    char *module_dir_string = NULL;
    MCRYPT td;

    //if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
    //    &cipher, &cipher_len, &module, &module_len) == FAILURE) {
    //    return;
    //}
	cipher  	= Tcl_GetStringFromObj(objv[1], &cipher_len );
	module		= Tcl_GetStringFromObj(objv[2], &module_len );

    td = mcrypt_module_open(getcipher(cipher), cipher_dir_string, getcipher(module), module_dir_string);
    if (td != MCRYPT_FAILED) {
        //RETVAL_LONG(mcrypt_enc_get_key_size(td));
  	    Tcl_SetObjResult(interp, Tcl_NewLongObj( mcrypt_enc_get_key_size(td) ) );
        mcrypt_module_close(td);
		return TCL_OK;
    } else {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, MCRYPT_OPEN_MODULE_FAILED);
		ERRORTCL("Module initialization failed");
		return TCL_ERROR;
    }
//}}}
}

//
TCL_FUNCTION(tcl_mcrypt_module_open) {
//{{{
    char *cipher, *cipher_dir;
    char *mode,   *mode_dir;
    int   cipher_len, cipher_dir_len;
    int   mode_len,   mode_dir_len;
    MCRYPT td;
    php_mcrypt *pm;
	Tcl_HashEntry *entryPtr;
	int new;
	char handleName[128];

    /*if (zend_parse_parameters (ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
        &cipher, &cipher_len, &cipher_dir, &cipher_dir_len,
        &mode,   &mode_len,   &mode_dir,   &mode_dir_len)) {
        return;
    }*/
	cipher  	= Tcl_GetStringFromObj(objv[1], &cipher_len );
	cipher_dir	= Tcl_GetStringFromObj(objv[2], &cipher_dir_len );
	mode		= Tcl_GetStringFromObj(objv[3], &mode_len );
	mode_dir	= Tcl_GetStringFromObj(objv[4], &mode_dir_len );
    td = mcrypt_module_open (
        getcipher(cipher),
        cipher_dir_len > 0 ? cipher_dir : algorithms_dir,
        getcipher(mode),
        mode_dir_len > 0 ? mode_dir : modes_dir
    );

    if (td == MCRYPT_FAILED) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Could not open encryption module");
    } else {
        pm = emalloc(sizeof(php_mcrypt));
        pm->td = td;
        pm->init = 0;

		sprintf(handleName,"mcrypt_%d",pm);
    	entryPtr = Tcl_CreateHashEntry( &bars, handleName, &new );
	    Tcl_SetHashValue( entryPtr, pm );

        //ZEND_REGISTER_RESOURCE(return_value, pm, le_mcrypt);
		Tcl_SetObjResult(interp, Tcl_NewStringObj(handleName,-1) );
    }

	return TCL_OK;
}

TCL_FUNCTION(tcl_mcrypt_module_close) {
	php_mcrypt *pm;
    Tcl_HashEntry *entryPtr;
	char *name;

    name = Tcl_GetStringFromObj(objv[1], NULL);
    entryPtr = Tcl_FindHashEntry( &bars, name );
	pm = Tcl_GetHashValue( entryPtr );

//	pm = (php_mcrypt *)entryPtr;	
//    name = Tcl_GetStringFromObj(objv[1], NULL);
//    pm = (php_mcrypt *)mcryptind;

	mcrypt_generic_deinit(pm->td);
    mcrypt_module_close(pm->td);

    Tcl_DeleteHashEntry( entryPtr );
	free(pm);

	return TCL_OK;
//}}}
}

/* {{{ proto int mcrypt_generic_init(resource td, string key, string iv)
   This function initializes all buffers for the specific module */
TCL_FUNCTION(tcl_mcrypt_generic_init) {
    char *key, *iv;
    int mcryptind;
    unsigned char *key_s, *iv_s;
    int max_key_size, key_size, iv_size;
	int nPointer;
    int argc;
    int result = 0;
    char *name;
    php_mcrypt *pm;
    Tcl_HashEntry *entryPtr;

    name = Tcl_GetStringFromObj(objv[1], NULL);
	key		= Tcl_GetStringFromObj(objv[2], &key_size );
    iv      = Tcl_GetStringFromObj(objv[3], &iv_size );

    entryPtr = Tcl_FindHashEntry( &bars, name );
    pm = Tcl_GetHashValue( entryPtr );

    //zend_get_parameters_ex(3, &mcryptind, &key, &iv);
    //ZEND_FETCH_RESOURCE(pm, php_mcrypt *, mcryptind, -1, "MCrypt", le_mcrypt);
    //convert_to_string_ex(key);
    //convert_to_string_ex(iv);

    max_key_size = mcrypt_enc_get_key_size(pm->td);
    iv_size = mcrypt_enc_get_iv_size(pm->td);

    if (Z_STRLEN_P(key) == 0) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Key size is 0");
    }

    key_s = emalloc(Z_STRLEN_P(key));
    memset(key_s, 0, Z_STRLEN_P(key));
    iv_s = emalloc(iv_size + 1);
    memset(iv_s, 0, iv_size + 1);

    if (Z_STRLEN_P(key) > max_key_size) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Key size too large; supplied length: %d, max: %d", Z_STRLEN_P(key), max_key_size);
        key_size = max_key_size;
    } else {
        key_size = Z_STRLEN_P(key);
    }
    memcpy(key_s, Z_STRVAL_P(key), Z_STRLEN_P(key));

    if (Z_STRLEN_P(iv) != iv_size) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Iv size incorrect; supplied length: %d, needed: %d", Z_STRLEN_P(iv), iv_size);
    }
    memcpy(iv_s, Z_STRVAL_P(iv), iv_size);

    mcrypt_generic_deinit(pm->td);
    result = mcrypt_generic_init(pm->td, key_s, key_size, iv_s);

    /* If this function fails, close the mcrypt module to prevent crashes
     * when further functions want to access this resource */
    if (result < 0) {
        //zend_list_delete(Z_LVAL_PP(mcryptind));
        switch (result) {
            case -3:
                //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Key length incorrect");
                break;
            case -4:
                //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Memory allocation error");
                break;
            case -1:
            default:
                //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown error");
                break;
        }
    }
//    RETVAL_LONG(result);
	Tcl_SetObjResult(interp, Tcl_NewLongObj(result) );

    efree(iv_s);
    efree(key_s);

	return TCL_OK;
}
/* }}} */

TCL_FUNCTION(tcl_mcrypt_generic) {
//{{{
    char *datax;
	int mcryptind;
    int argc;
    unsigned char* data_s;
    int block_size, data_size;
	int nRc;
	int newlen;
	char *dest;
    char *name;
    php_mcrypt *pm;
    Tcl_HashEntry *entryPtr;

    name = Tcl_GetStringFromObj(objv[1], NULL);
    datax   = Tcl_GetStringFromObj(objv[2], &data_size );
    entryPtr = Tcl_FindHashEntry( &bars, name );
    pm = Tcl_GetHashValue( entryPtr );

    /* Check blocksize */
    if (mcrypt_enc_is_block_mode(pm->td) == 1) { /* It's a block algorithm */
        block_size = mcrypt_enc_get_block_size(pm->td);
        data_size = (((Z_STRLEN_P(datax) - 1) / block_size) + 1) * block_size;
        data_s = emalloc(data_size + 1);
        memset(data_s, 0, data_size);
        memcpy(data_s, Z_STRVAL_P(datax), Z_STRLEN_P(datax));
    } else { /* It's not a block algorithm */
        data_size = Z_STRLEN_P(datax);
        data_s = emalloc(data_size + 1);
        memset(data_s, 0, data_size);
        memcpy(data_s, Z_STRVAL_P(datax), Z_STRLEN_P(datax));
    }

    mcrypt_generic(pm->td, data_s, data_size);
//	mcrypt_generic_end(pm->td);
//    data_s[data_size] = '\0';

//    RETVAL_STRINGL(data_s, data_size, 1);
	dest = BIN2HEX(data_s, data_size-1, &newlen);
	dest[newlen] = '\0';

	Tcl_SetObjResult(interp, Tcl_NewStringObj(dest, newlen));
	efree(dest);
    efree(data_s);

	return TCL_OK;
//}}}
}
/* }}} */

TCL_FUNCTION(tcl_mcrypt_generic_deinit) {
//{{{
    char *name;
    php_mcrypt *pm;
    Tcl_HashEntry *entryPtr;

    name = Tcl_GetStringFromObj(objv[1], NULL);
    entryPtr = Tcl_FindHashEntry( &bars, name );
    pm = Tcl_GetHashValue( entryPtr );

	mcrypt_generic_end(pm->td);
    if (mcrypt_generic_deinit(pm->td) < 0) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Could not terminate encryption specifier");
    }
	return TCL_OK;
//}}}
}

//
TCL_FUNCTION(tcl_mcrypt_get_iv_size) {
//{{{
    char *cipher;
    char *module;
    int   cipher_len, module_len;
    char *cipher_dir_string;
    char *module_dir_string;
    MCRYPT td;

    cipher_dir_string = NULL;
    module_dir_string = NULL;

	cipher  	= Tcl_GetStringFromObj(objv[1], &cipher_len );
	module		= Tcl_GetStringFromObj(objv[2], &module_len );

    td = mcrypt_module_open(getcipher(cipher), cipher_dir_string, getcipher(module), module_dir_string);
    if (td != MCRYPT_FAILED) {
//        RETVAL_LONG(mcrypt_enc_get_iv_size(td));
		Tcl_SetObjResult(interp, Tcl_NewLongObj( mcrypt_enc_get_iv_size(td) ) );

        mcrypt_module_close(td);
    } else {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, MCRYPT_OPEN_MODULE_FAILED);
		//printf("%d", MCRYPT_FAILED);
    }

	return TCL_OK;
//}}}
}

/* {{{ proto string mcrypt_create_iv(int size, int source)
   Create an initialization vector (IV) */
TCL_FUNCTION(tcl_mcrypt_create_iv) {
//{{{
    char *iv;
	char *dest;
	char *str;
    long source = RANDOM;
    long size;
    int n = 0;
	int nRc;
	int newlen;

	nRc 	= Tcl_GetLongFromObj(interp,objv[1], &size );
	str		= Tcl_GetStringFromObj(objv[2], NULL );
	
	if ( strcmp("MCRYPT_DEV_RANDOM",str) == 0 ) {
		source = 0;
	}
	if ( strcmp("MCRYPT_DEV_URANDOM",str) == 0 ) {
		source = 1;
	}
	if ( strcmp("MCRYPT_RAND",str) == 0 ) {
		source = 2;
	}

    if (size <= 0 || size >= INT_MAX) {
        //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Can not create an IV with a size of less then 1 or greater then %d", INT_MAX);
		return TCL_ERROR;
    }

    iv = ecalloc(size + 1, 1);

    if (source == RANDOM || source == URANDOM) {
        int    fd;
        size_t read_bytes = 0;

        fd = open(source == RANDOM ? "/dev/random" : "/dev/urandom", O_RDONLY);
        if (fd < 0) {
            efree(iv);
            //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Cannot open source device");
            //RETURN_FALSE;
			return TCL_ERROR;
        }
        while (read_bytes < size) {
            n = read(fd, iv + read_bytes, size - read_bytes);
            if (n < 0) {
                break;
            }
            read_bytes += n;
        }
        n = read_bytes;
        close(fd);
        if (n < size) {
            efree(iv);
            //php_error_docref(NULL TSRMLS_CC, E_WARNING, "Could not gather sufficient random data");
			return TCL_ERROR;
        }
    } else {
        n = size;
        while (size) {
            iv[--size] = 255.0 * php_rand() / RAND_MAX;
        }
    }

	dest = BIN2HEX(iv, n, &newlen);

    //RETURN_STRINGL(iv, n, 0);
	Tcl_SetObjResult(interp, Tcl_NewStringObj(dest, newlen));

	free(iv);
	free(dest);

	return TCL_OK;
//}}}
}

//
TCL_FUNCTION(tcl_mcrypt_encrypt) {
//{{{
    char *cipher, *key, *datax, *mode, *iv;
	unsigned char *enc = NULL;
	unsigned char *dest = NULL;
	size_t newlen;

    cipher  = Tcl_GetStringFromObj(objv[1], NULL);
    key     = Tcl_GetStringFromObj(objv[2], NULL);
    datax	= Tcl_GetStringFromObj(objv[3], NULL);
    mode	= Tcl_GetStringFromObj(objv[4], NULL);
    iv		= Tcl_GetStringFromObj(objv[5], NULL);

    enc 	= php_mcrypt_do_crypt(getcipher(cipher), key, datax, getcipher(mode), iv, objc, MCRYPT_ENCRYPT );
	if ( enc == NULL ) {
		ERRORTCL("Module initialization failed");
		return TCL_ERROR;
	} 
	dest = BIN2HEX(enc, strlen(enc)-1, &newlen);

	Tcl_SetObjResult(interp, Tcl_NewStringObj(dest, -1));
	
	free(enc);
	free(dest);

	return TCL_OK;
//}}}
}

//
TCL_FUNCTION(tcl_mcrypt_decrypt) {
//{{{
    char *cipher, *key, *datax, *mode, *iv;
	unsigned char *enc = NULL;
	unsigned char *dest = NULL;
	int datalen;

    cipher  = Tcl_GetStringFromObj(objv[1], NULL);
    key     = Tcl_GetStringFromObj(objv[2], NULL);
    datax	= Tcl_GetStringFromObj(objv[3], &datalen );
    mode	= Tcl_GetStringFromObj(objv[4], NULL);
    iv		= Tcl_GetStringFromObj(objv[5], NULL);

	enc = HEX2BIN(datax,datalen);
	if ( enc == NULL ) {
		ERRORTCL("hex to bin convert failed");
		return TCL_ERROR;
	} 
    dest   = php_mcrypt_do_crypt(getcipher(cipher), key, enc, getcipher(mode), iv, objc, MCRYPT_DECRYPT );
	if ( dest == NULL ) {
		ERRORTCL("Module initialization failed");
		return TCL_ERROR;
	}

	Tcl_SetObjResult(interp, Tcl_NewStringObj(dest, strlen(dest)));
	
	free(enc);
	free(dest);

	return TCL_OK;
//}}}
}

//Init
int Mcrypt_Init(Tcl_Interp* interp) {

	Tcl_InitHashTable( &bars, TCL_STRING_KEYS );

    Tcl_CreateObjCommand(interp, "mcrypt", tcl_mcrypt, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_list_algorithms", tcl_mcrypt_list_algorithms, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_list_modes", tcl_mcrypt_list_modes, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_get_key_size", tcl_mcrypt_get_key_size, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_module_close", tcl_mcrypt_module_close, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_generic_init", tcl_mcrypt_generic_init, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_generic", tcl_mcrypt_generic, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_generic_deinit", tcl_mcrypt_generic_deinit, NULL, NULL);

    Tcl_CreateObjCommand(interp, "mcrypt_module_open", tcl_mcrypt_module_open, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_get_iv_size", tcl_mcrypt_get_iv_size, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_create_iv", tcl_mcrypt_create_iv, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_encrypt", tcl_mcrypt_encrypt, NULL, NULL);
    Tcl_CreateObjCommand(interp, "mcrypt_decrypt", tcl_mcrypt_decrypt, NULL, NULL);

    Tcl_PkgProvide(interp, "mcrypt", "1.0");

    return TCL_OK;
}
