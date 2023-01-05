// HookEliminator.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "HookEliminator.h"


// This is an example of an exported variable
HOOKELIMINATOR_API int nHookEliminator=0;

// This is an example of an exported function.
HOOKELIMINATOR_API int fnHookEliminator(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CHookEliminator::CHookEliminator()
{
    return;
}
