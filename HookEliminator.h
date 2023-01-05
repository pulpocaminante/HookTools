// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the HOOKELIMINATOR_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// HOOKELIMINATOR_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef HOOKELIMINATOR_EXPORTS
#define HOOKELIMINATOR_API __declspec(dllexport)
#else
#define HOOKELIMINATOR_API __declspec(dllimport)
#endif

// This class is exported from the dll
class HOOKELIMINATOR_API CHookEliminator {
public:
	CHookEliminator(void);
	// TODO: add your methods here.
};

extern HOOKELIMINATOR_API int nHookEliminator;

HOOKELIMINATOR_API int fnHookEliminator(void);
