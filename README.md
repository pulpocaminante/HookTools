# HookTools
Basic injectable for analyzing the behavior of evasive malware

Requires Microsoft Detours
https://github.com/microsoft/Detours

In addition to a DLL and process loading/access blocklist, it has the following toggleable features:


Allow process to grab module names

Allow process to open handles to other processes

Allow the process to use OpenProcess to get a handle to itself

Allow process to snapshot any process

Allow process to snapshot itself

Allow process to make global hooks
