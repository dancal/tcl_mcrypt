#include <tcl.h>

#define	ERRORTCL(msg) error_tcl_message(interp,msg);
#define	VIOLATION(msg) error_tcl_message(interp,msg);

void error_tcl_message( Tcl_Interp *interp, char *msg );
