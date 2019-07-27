---
layout: post
title: Enabling Covert Operations - 0: Dynamic Invocation & Modular Shellcode Injection
---

*TLDR: The first in an irregularly updated blog series on enhancing open-source tooling through contributions to SharpSploit that enable covert, all-in-memory operations. First up, how to dynamically invoke unmanaged code from memory or disk while (mostly) avoiding P/Invoke and suspicious imports, as well as three modular C# implementations of convert remote injection techniques.*

# Dynamic Invocation - D/Invoke

## Not Actually New

### A Legitimate Technique

### Delegates

## Why?

### Avoid Suspicious Imports

### Unknown Execution Flow at Compile Time

### Shellcode Execution

### Manual Mapping

## How?

# Covert Remote Injection

## General Tradecraft & Techniques

### Only ntdll.dll

### Section Mapping

### Local Views

### RWX || RX?

### Still Room For Improvement

## Design Philosophy

### Modularity

### Who Should Choose How A Tool Can Be Used: The Designer or the Operator?

## Implementation

### Remote Thread Creation

### APC Injection

### Threat Hijacking

# Conclusions

Next up, how to use D/Invoke to use exported functions from memory-mapped unmanaged DLLs... entirely from memory. Completely bypasses API Hooking and enables using DLLs reflectively.

* Import everything in the IAT
* Function Hashing (Maru)
* P/Invoke Innocuous API calls to force a library to load. Then use GetModuleHandle & GetProcAddress.
* Manually Map DLL