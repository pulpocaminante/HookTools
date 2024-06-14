# HookTools

## Overview
HookTools is a compact yet powerful tool designed to aid in the analysis of extremely evasive malware. By leveraging various hooks and access control mechanisms, HookTools simplifies the process of understanding some sophisticated malware.

## Features
HookTools comes with a series of toggleable features:
- **Module Name Access**: Allow the analyzed process to retrieve the names of loaded modules.
- **Handle Access**: Permit the process to open handles to other processes.
- **Self Handle Access**: Enable the process to use OpenProcess to obtain a handle to itself.
- **Process Snapshotting**: Allow the process to create snapshots of any running process.
- **Self Snapshotting**: Allow the process to create snapshots of itself.
- **Global Hooking**: Enable the process to set global hooks.

## Requirements
To use HookTools, the following dependency is required:
- **Microsoft Detours**: A library for intercepting and instrumenting functions on Windows. It can be found [here](https://github.com/microsoft/Detours).
