---
layout: post
title: Enabling Covert Operations - 0: Dynamic Invocation
---

*TLDR: The first (and late) post in an irregularly updated blog series on enhancing open-source tooling through contributions to SharpSploit that enable covert, all-in-memory operations. Nothing in this series will be operation-ready. I will provide you knowledge and ingredients, but you must do the work to build operational tooling upon it. First up, how to dynamically invoke unmanaged code from memory or disk while (mostly) avoiding P/Invoke and suspicious imports, as well as an example that performs remote shellcode injection without Pinvoking suspicious API calls.*

# Dynamic Invocation - D/Invoke

On August 5th, [cobbr](https://twitter.com/cobbr_io) merged a [Pull Request](https://github.com/cobbr/SharpSploit/pull/21) of mine into SharpSploit that helps you use unmanaged code from C# while avoiding suspicious P/Invokes. Rather than statically importing API calls with PInvoke, you may use Dynamic Invocation (I call it DInvoke) to load the DLL at runtime and call the function using a pointer to its location in memory. This avoids detections that look for imports of suspicious API calls via the Import Address Table in the .NET Assembly's PE headers. Additionally, it lets you call unmanaged code from memory (while passing parameters on the stack) without resorting to dynamically building and running shellcode.

## Not Actually New

I am not the first offensive tool developer to use this technique. However, since it is new to SharpSploit and I have not seen anyone discuss it before, I decided it was worth a post.

### A Legitimate Technique

Nothing about this technique is inherently malicious. If you are experienced in writing Windows applications, then you may be surprised that I even discuss this as an offensive "technique". It is the standard way of using DLLs in Windows. The only reason this is useful offensively is because it happens to circumvent a few common detection techniques. And the way that it was implement in SharpSploit also makes it easier to use unmanaged code from memory. Which, again, is not necessarily malicious but is useful for malware writers.

### Delegates

## Why?

### Avoid Suspicious Imports

### Unknown Execution Flow at Compile Time

### Shellcode Execution

### Manual Mapping

## How?

.NET APIs involved. Explain the functions and implementation in SharpSploit.

## Example - NtInjector

Let's walk through an example. We will build a shellcode injector that only uses API calls from `ntdll.dll`, but does not use any PInvokes from that DLL. It does not implement any new injection technique. The complete project is not available for download, but you may build a tool from it yourself as an exercise.

## Room for Improvement

* P/Invoke Innocuous API calls to force a library to load. Then use GetModuleHandle & GetProcAddress.
* Using a PE reader to get the symbol addresses
* Walking the PEB / API hashing

## Conclusion

Next up, a modular shellcode injection library for SharpSploit.

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

### Win32/NT API Call Table

The table below explains every Windows API call that is used in this code. Name, description, usage, works on remote processes, CFG-evasion, CIG-evasion. 

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
