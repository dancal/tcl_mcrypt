#include "tcl_compat.h"

void error_tcl_message( Tcl_Interp *interp, char *msg ) {
    Tcl_Obj     *lpobjErr;
    lpobjErr = Tcl_NewStringObj( msg, strlen(msg) );
    Tcl_SetObjResult( interp, lpobjErr );
}

