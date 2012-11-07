#include "php_compat.h"

long php_rand() {
    long ret;
//    ret = random();
    ret = lrand48();
    //ret = rand();
    return ret;
}

char *zend_strndup(const char *s, uint length) {
    char *p;

    p = malloc(length+1);
    if (!p) {
        return (char *)NULL;
    }
    if (length) {
        memcpy(p, s, length);
    }
    p[length] = 0;
    return p;
}

char *zend_memnstr(char *haystack, char *needle, int needle_len, char *end) {
    char *p = haystack;
    char ne = needle[needle_len-1];

    end -= needle_len;

    while (p <= end) {
        if ((p = (char *)memchr(p, *needle, (end-p+1))) && ne == p[needle_len-1]) {
            if (!memcmp(needle, p, needle_len-1)) {
                return p;
            }
        }

        if (p == NULL) {
            return NULL;
        }
        p++;
    }
    return NULL;
}

char x2b(char c) {
	if(c>='0' && c<='9')
  		return c-'0';
	else if (c>='A' && c<='F')
		return c-'A'+0xa;
	else if (c>='a' && c<='f')
		return c-'a'+0xa;
	return -1; // error
}

char *hex2bin(char *hexstring, int maxbuf) {
	char *buf;
    char *pc=hexstring;
    int i=0;
    int byte=-1; // -1 empty

	buf = (char *) safe_emalloc(maxbuf, sizeof(char), 1);	
	memset(buf,0x00,sizeof(buf));
	while(*pc!='\0' && i<maxbuf ) {
          if( isxdigit(*pc) )
          {
               if(byte == -1)
               {
                    byte = x2b(*pc);
               }
              else
              {
                    buf[i] = byte<<4 | x2b(*pc);
                    i++;
                    byte = -1;
              }
         }
         else
         {
               if(byte != -1)
               {
                    buf[i]= byte;
                    i++;
                    byte = -1;
               }
         }    
         pc++;
    }
    return buf;
}

char *php_bin2hex(const unsigned char *old, const size_t oldlen, size_t *newlen) {
    register unsigned char *result = NULL;
    size_t i, j;

    result = (char *) safe_emalloc(oldlen * 2, sizeof(char), 1);
	memset(result,0x00,sizeof(result));

    for (i = j = 0; i < oldlen; i++) {
        result[j++] = hexconvtab[old[i] >> 4];
        result[j++] = hexconvtab[old[i] & 15];
    }
    result[j] = '\0';

    if (newlen)
        *newlen = oldlen * 2 * sizeof(char);

    return result;
}
