---
layout: post
title: Enabling Covert Operations - 0: Dynamic Invocation (Avoiding PInvoke)
---

*TLDR: The first (and late) post in an irregularly updated blog series on enhancing open-source tooling through contributions to SharpSploit that enable covert, all-in-memory operations. Nothing in this series will be operation-ready. I will provide you knowledge and ingredients, but you must do the work to build operational tooling upon it. First up, how to dynamically invoke unmanaged code from memory or disk while (mostly) avoiding P/Invoke and suspicious imports, as well as an example that performs remote shellcode injection without Pinvoking suspicious API calls.*

# Dynamic Invocation - D/Invoke

On August 5th, [cobbr](https://twitter.com/cobbr_io) merged a [Pull Request](https://github.com/cobbr/SharpSploit/pull/21) of mine into SharpSploit that helps you use unmanaged code from C# while avoiding suspicious P/Invokes. Rather than statically importing API calls with PInvoke, you may use Dynamic Invocation (I call it DInvoke) to load the DLL at runtime and call the function using a pointer to its location in memory. This avoids detections that look for imports of suspicious API calls via the Import Address Table in the .NET Assembly's PE headers. Additionally, it lets you call unmanaged code from memory (while passing parameters on the stack) without resorting to dynamically building and running shellcode.

## Not Actually New

I am not the first offensive tool developer to use this technique. However, since it is new to SharpSploit and I have not seen anyone discuss it before in the context of C#, I decided it was worth a post.

### A Legitimate Technique

Nothing about this technique is inherently malicious. If you are experienced in writing Windows applications, then you may be surprised that I even discuss this as an offensive "technique". It is the standard way of using DLLs in Windows. The only reason this is useful offensively is because it happens to circumvent a few common detection techniques. And the way that it was implement in SharpSploit also makes it easier to use unmanaged code from memory. Which, again, is not necessarily malicious but is useful for malware writers.

### Delegates

So what does DInvoke actually entail? Rather than using PInvoke to import the API calls that we want to use, we PInvoke only two API calls: `LoadLibrary` and `GetProcAddress`. The former loads a DLL from disk into your current process. The latter gets a pointer to a function in a DLL that has been loaded into the current process. We may call that function from the pointer while passing in our parameters on the stack.

Again, you may be thinking that this process is nothing new. You are correct. However, what is new is a SharpSploit API that automates this process for making arbitrary API calls with the goal of directly replacing PInvoke. By leveraging this dynamic loading API rather than the static loading API that sits behind PInvoke, you avoid directly importing suspicious API calls into your .NET Assembly. Additionally, this API lets you easily invoke unmanaged code from memory in C# (passing in parameters and receiving output) without doing some hacky workaround like self-injecting shellcode.

We accomplish this through the magic of [Delegates](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/). .NET includes the Delegate API as a way of wrapping a method/function in a class. If you have ever used the Reflection API to enumerate methods in a class, the objects you were inspecting were actually a form of delegate.

The Delegate API has a number of fantastic features, such as the ability to instantiate Delegates from function pointers and to dynamically invoke the function wrapped by the delegate while passing in parameters. 

Let's take a look at some of the code in this API:

```csharp

/// <summary>
        /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="DLLName">Name of the DLL.</param>
        /// <param name="FunctionName">Name of the function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {
            IntPtr hModule = Execution.Win32.Kernel32.LoadLibrary(DLLName);

            IntPtr pFunction = Execution.Win32.Kernel32.GetProcAddress(hModule, FunctionName);

            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pFunction, FunctionDelegateType);

            Object result = funcDelegate.DynamicInvoke(Parameters);

            return result;
        }

```

This method has been reduced to effectively four lines of code. The first creates a Delegate from a function pointer that is discovered through a combination of `LoadLibrary` and `GetProcAdress`. The second invokes the function wrapped by the delegate, passing in parameters provided by you. The parameters are passed in as an array of Objects so that you can pass in whatever data you need in whatever form. You must take care to ensure that the data passed in is structured in the way that the unmanaged code will expect.

The confusing part of this is probably the `Type FunctionDelegateType` parameter. This is where you pass in the function prototype of the unmanaged code that you want to call. If you remember from PInvoke, you set up the function with something like:

```csharp
[DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(
                ProcessAccessFlags dwDesiredAccess,
                bool bInheritHandle,
                UInt32 dwProcessId
            );
```

You must also pass in a function prototype for DInvoke. This lets the Delegate know how to set up the stack when it invokes the function. If you compare this to how you would normally invoke unmanaged code from memory in C# (by self-injecting shellcode), this is MUCH easier!

The code below demonstrates how this is used for the `NtCreateThreadEx` function in `ntdll.dll`. The delegate (that sets up the function prototype) is stored in the `SharpSploit.Execution.DynamicInvoke.Native.DELEGATES` struct. The wrapper method is `SharpSploit.Execution.DynamicInvoke.Native.NtCreateThreadEx` that takes all of the same parameters that you would expect to use in a normal PInvoke.

```csharp

namespace SharpSploit.Execution.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
    /// </summary>
    public class Native
    {        
        /// <summary>
        /// Holds delegates for API calls in the NT Layer.
        /// Must be public so that they may be used with SharpSploit.Execution.DynamicInvoke.Generic.DynamicFunctionInvoke
        /// </summary>
        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr NtCreateThreadEx(out IntPtr threadHandle, Execution.Win32.WinNT.ACCESS_MASK desiredAccess,
                IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter,
                Execution.Win32.NtDll.NT_CREATION_FLAGS creationFlags, int stackZeroBits, int sizeOfStack, int maximumStackSize,
                IntPtr attributeList);
        }
    }

```

So how do you actually use this API? A number of ways:

#### "Statically"

We are building a second set of function prototypes in SharpSploit. There is already a PInvoke library; we will now build a DInvoke library in the `SharpSploit.Execution.DynamicInvoke` namespace. The DInvoke library provides a managed wrapper function for each unmanaged function. The wrapper helps the user by ensuring that parameters are passed in correctly and the correct type of object is returned.

It is worth noting: PInvoke is MUCH more forgiving about data types than DInvoke. If the data types you specify in a PInvoke function prototype are not *quite* right, it will silently correct them for you. With DInvoke that is not the case. You must marshal data in *exactly* the correct way, ensuring that the data structures you pass in are in the same format as the unmanaged code expects. This is annoying. And is part of why we created a seperate namespace for DInvoke signatures and wrappers. If you want to understand better how to marshal data for PInvoke/DInvoke, I would recommend reading @matterpreter's [blog post on the subject](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d).

```csharp
namespace SharpSploit.Execution.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
    /// </summary>
    public class Native
    {     
        public static IntPtr NtCreateThreadEx(ref IntPtr threadHandle, Execution.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter,
            Execution.Win32.NtDll.NT_CREATION_FLAGS creationFlags, int stackZeroBits, int sizeOfStack, int maximumStackSize,
            IntPtr attributeList)
        { 
            //Craft an array for the arguments
            object[] funcargs =
            {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, creationFlags, stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList
            };

            return (IntPtr)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateThreadEx",
                typeof(DELEGATES.NtCreateThreadEx), ref funcargs);
        }
    }
}
```

You may use this wrapper to dynamically call `NtCreateThreadEx` as if you were calling any other managed function: 

**TODO: Correct syntax**

```csharp
//Invoke NtCreateThreadEx using the delegate
SharpSploit.Execution.DynamicInvoke.Native.NtCreateThreadEx(
        out threadHandle, AccessMask.SpecificRightsAll | AccessMask.StandardRightsAll, IntPtr.Zero,
        procHandle, startAddress, IntPtr.Zero, CreationFlags.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
```

#### "Dynamically".

You may also use these delegates to invoke unmanaged functions without a managed wrapper. 

```csharp
 //Get a pointer to the NtCreateThreadEx function.
        IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");
        
        //Create an instance of a NtCreateThreadEx delegate from our function pointer.
        DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
           pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));
        
        //Invoke NtCreateThreadEx using the delegate
        createThread(ref threadHandle, Execution.Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Execution.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
                procHandle, startAddress, IntPtr.Zero, Execution.Win32.NtDll.NT_CREATION_FLAGS.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
```

If you wish to use your 

## Why?

DInvoke presents several opportunities for offensive tool developers.

### Avoid Suspicious Imports

As previously mentioned, you can avoid statically importing suspicious API calls. If, for example, you wanted to import `MiniDumpWriteDump` from `Dbghelp.dll` you could use our api to dynamically load the DLL and invoke the API call. If you were then to inspect your .NET Assembly in an Assembly dissassembler, you would find that `MiniDumpWriteDump` is not referenced in its import table.

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
