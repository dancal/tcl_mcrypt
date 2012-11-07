#define SIZEOF_UNSIGNED_LONG_INT 4

int le_h;
char *modes_dir;
char *algorithms_dir;

static int le_mcrypt;

typedef struct _php_mcrypt {
    MCRYPT td;
    int init;
} php_mcrypt;

typedef enum {
    RANDOM = 0,
    URANDOM,
    RAND
} iv_source;
