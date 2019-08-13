---
layout: post
title: Enabling Covert Operations - 0: Dynamic Invocation
---

*TLDR: The first in an irregularly updated blog series on enhancing open-source tooling through contributions to SharpSploit that enable covert, all-in-memory operations. First up, how to dynamically invoke unmanaged code from memory or disk while (mostly) avoiding P/Invoke and suspicious imports, as well as three modular C# implementations of convert remote injection techniques.*

# Dynamic Invocation - D/Invoke

## Not Actually New

* P/Invoke Innocuous API calls to force a library to load. Then use GetModuleHandle & GetProcAddress.

### A Legitimate Technique

### Delegates

## Why?

### Avoid Suspicious Imports

### Unknown Execution Flow at Compile Time

### Shellcode Execution

### Manual Mapping

## How?

---
layout: post
title: Enabling Covert Operations - 1: Modular Shellcode Injection
---

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

## Implementation in SharpSploit

### Remote Thread Creation

### APC Injection

### Threat Hijacking

### General Remote Injection

---
layout: post
title: Enabling Covert Operations - 2: Manually Mapping DLLs (Unmanaged Reflection)
---
Create a set of classes for discovering and using symbols in unmanaged DLLs. Have an `UnmanagedPE` class with:

* UnmanangedPE(byte[] PEBytes)
* UnmanagedPE.Import(byte[] PEBytes) //
* private Unmanaged.SymbolStore //public get

* SymbolStore
* private byte[] SymbolStore.PEBytes // with public get
* public bool SymbolStore.Discover(byte[] PEBytes) //Fills the store with Symbols
* private Symbol[] SymbolStore.Symbols //Set of symbols advertised by the IAT
* public Symbol SymbolStore.FindSymbol(string symbolName)

* Symbol
* public string[] Symbol.Name //Symbol names(s)
* public delegate Symbol.Signature //Delegate
* public int Symbol.RelativeOffset //Offset from the base address of the module
* public IntPtr Symbol.Ptr //Absolute virtual address

* Import everything in the IAT
* Function Hashing (Maru)
* Manually Map DLL

---
layout: post
title: Enabling Covert Operations - 3: Easily Using Arbitrary Syscalls from Managed Code
---

# Conclusions

Next up, how to use D/Invoke to use exported functions from memory-mapped unmanaged DLLs... entirely from memory. Completely bypasses API Hooking and enables using DLLs reflectively.
