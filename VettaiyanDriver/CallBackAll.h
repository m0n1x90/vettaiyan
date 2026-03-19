#ifndef CALLBACK_ALL_H
#define CALLBACK_ALL_H

/*
 * CallBackAll.h -- one include to pull in every kernel callback module.
 * Driver.c includes this so it doesn't need to list them individually.
 */

#include "CallBackImage.h"      /* DLL/image load notifications */
#include "CallBackProcess.h"    /* Process create/terminate */
#include "CallBackThread.h"     /* Thread create/terminate */
#include "CallBackRegistry.h"   /* Registry key/value changes */
#include "CallBackObject.h"     /* Handle create/duplicate */

#endif