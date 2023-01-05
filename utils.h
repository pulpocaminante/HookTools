#pragma once
#include "pch.h"
#include <string>
#include <tchar.h>
#include <TlHelp32.h>
#include <iostream>

BOOL isPartOf(const char* w1, const char* w2);
BOOL ListProcessThreads(DWORD dwOwnerPID);
void printError(LPCWSTR msg);
