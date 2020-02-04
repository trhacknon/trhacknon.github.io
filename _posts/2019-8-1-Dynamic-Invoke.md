---
layout: post
title: Enabling Covert Operations - 0: Dynamic Invocation (Avoiding PInvoke)
---

*TLDR: How to dynamically invoke unmanaged code from memory or disk while avoiding API Hooking and suspicious imports, as well as an example that performs remote shellcode injection without Pinvoking suspicious API calls.*

# Dynamic Invocation - D/Invoke

Over the past few months, myself and b33f (@FuzzySecurity, Ruben Boonen) have quitely been adding an API to SharpSploit that helps you use unmanaged code from C# while avoiding suspicious P/Invokes. Rather than statically importing API calls with PInvoke, you may use Dynamic Invocation (I call it DInvoke) to load the DLL at runtime and call the function using a pointer to its location in memory. This avoids detections that look for imports of suspicious API calls via the Import Address Table in the .NET Assembly's PE headers. Additionally, it lets you call arbitrary unmanaged code from memory (while passing parameters on the stack), allowing you to bypass API hooking in a variety of ways. Overall. DInvoke is intended to be a direct replacement for PInvoke that gives offensive tool developers great flexibility in how they can access and invoke unmanaged code. 

## Delegates

So what does DInvoke actually entail? Rather than using PInvoke to import the API calls that we want to use, we use any way we would like to load a DLL into memory. Then, we get a pointer to a function in that DLL. We may call that function from the pointer while passing in our parameters.

By leveraging this dynamic loading API rather than the static loading API that sits behind PInvoke, you avoid directly importing suspicious API calls into your .NET Assembly. Additionally, this API lets you easily invoke unmanaged code from memory in C# (passing in parameters and receiving output) without doing some hacky workaround like self-injecting shellcode.

We accomplish this through the magic of [Delegates](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/). .NET includes the Delegate API as a way of wrapping a method/function in a class. If you have ever used the Reflection API to enumerate methods in a class, the objects you were inspecting were actually a form of delegate.

The Delegate API has a number of fantastic features, such as the ability to instantiate Delegates from function pointers and to dynamically invoke the function wrapped by the delegate while passing in parameters. 

Let's take a look at how DInvoke uses these Delegates:

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
    IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
    return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
}

/// <summary>
/// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
/// </summary>
/// <author>The Wover (@TheRealWover)</author>
/// <param name="FunctionPointer">A pointer to the unmanaged function.</param>
/// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
/// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
/// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
{
    Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
    return funcDelegate.DynamicInvoke(Parameters);
}

```

These two functions are the core of the DInvoke API. The second is the most important. It creates a Delegate from a function pointer and invokes the function wrapped by the delegate, passing in parameters provided by you. The parameters are passed in as an array of Objects so that you can pass in whatever data you need in whatever form. You must take care to ensure that the data passed in is structured in the way that the unmanaged code will expect.

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

Defining a delegate works in a similar manner. You can define a delegate similar to how you would define a variable. Optionally, you can specify what calling convention to use when calling the function wrapped by the delegate.

```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 NtOpenProcess(
    ref IntPtr ProcessHandle,
    Execute.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
    ref Execute.Native.OBJECT_ATTRIBUTES ObjectAttributes,
    ref Execute.Native.CLIENT_ID ClientId);
```

## Using DInvoke

### Executing Code

We are building a second set of function prototypes in SharpSploit. There is already a PInvoke library; we will now build a DInvoke library in the `SharpSploit.Execution.DynamicInvoke` namespace. The DInvoke library provides a managed wrapper function for each unmanaged function. The wrapper helps the user by ensuring that parameters are passed in correctly and the correct type of object is returned.

It is worth noting: PInvoke is MUCH more forgiving about data types than DInvoke. If the data types you specify in a PInvoke function prototype are not *quite* right, it will silently correct them for you. With DInvoke that is not the case. You must marshal data in *exactly* the correct way, ensuring that the data structures you pass in are in the same format as the unmanaged code expects. This is annoying. And is part of why we created a seperate namespace for DInvoke signatures and wrappers. If you want to understand better how to marshal data for PInvoke/DInvoke, I would recommend reading @matterpreter's [blog post on the subject](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d).

The code below demonstrates how DInvoke is used for the `NtCreateThreadEx` function in `ntdll.dll`. The delegate (that sets up the function prototype) is stored in the `SharpSploit.Execution.DynamicInvoke.Native.DELEGATES` struct. The wrapper method is `SharpSploit.Execution.DynamicInvoke.Native.NtCreateThreadEx` that takes all of the same parameters that you would expect to use in a normal PInvoke.

```csharp

namespace SharpSploit.Execution.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
    /// </summary>
    public class Native
    {
        public static Execute.Native.NTSTATUS NtCreateThreadEx(
            ref IntPtr threadHandle,
            Execute.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes, IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateThreadEx",
                typeof(DELEGATES.NtCreateThreadEx), ref funcargs);

            // Update the modified variables
            threadHandle = (IntPtr)funcargs[0];

            return retValue;
        }

```

You may use this wrapper to dynamically call `NtCreateThreadEx` as if you were calling any other managed function: 

```csharp
IntPtr threadHandle = new IntPtr();

//Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
result = DynamicInvoke.Native.NtCreateThreadEx(ref threadHandle, Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
                    process.Handle, baseAddr, IntPtr.Zero, suspended, 0, 0, 0, IntPtr.Zero);

// The "threadHandle" variable will now be updated with a pointer to the handle for the new thread. 
```

You can, of course, manually use the Delegates in the DInvoke library without the use of our helper functions.

```csharp
 //Get a pointer to the NtCreateThreadEx function.
IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");

//Create an instance of a NtCreateThreadEx delegate from our function pointer.
DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
   pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));

//Invoke NtCreateThreadEx using the delegate
createThread(ref threadHandle, Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
                    process.Handle, baseAddr, IntPtr.Zero, suspended, 0, 0, 0, IntPtr.Zero);
```

### Loading Code
The section above shows how you would use Delegates and the DInvoke API. But how do you obtain the address for a function in the first place. The answer to that question really is: *however you would like*. But, to make that process easier, we have have provided a suite of tools to help you locate and call code using a variety of mechanisms.

The easiest way to locate and execute a function is to use the `DynamicAPIInvoke` function shown above in the first code example. It uses `GetLibraryAddress` to locate a function.

`GetLibraryAddress`: First, checks if the module is already loaded using `GetLoadedModuleAddress`. If not, it loads the module into the process using `LoadModuleFromDisk`, which uses the NT API call `LdrLoadDll` to load the DLL. 
`GetLoadedModuleAddress`: Uses `Process.GetCurrentProcess().Modules` to check if a module on disk is already loaded into the current process.
`LoadModuleFromDisk`: This will generate an Image Load ("modload") event for the process, which could be used as part of a detection signal.

## Why?

DInvoke presents several opportunities for offensive tool developers.

### Avoid Suspicious Imports

As previously mentioned, you can avoid statically importing suspicious API calls. If, for example, you wanted to import `MiniDumpWriteDump` from `Dbghelp.dll` you could use our api to dynamically load the DLL and invoke the API call. If you were then to inspect your .NET Assembly in an Assembly dissassembler, you would find that `MiniDumpWriteDump` is not referenced in its import table.

### Manual Mapping

### Unknown Execution Flow at Compile Time

### Shellcode Execution

Demonstrated in the Shellcode executor in SharpSploit.

## How?

.NET APIs involved. Explain the functions and implementation in SharpSploit.

## Example - NtInjector

Let's walk through an example. We will build a shellcode injector that only uses API calls from `ntdll.dll`, but does not use any PInvokes from that DLL. It does not implement any new injection technique. The complete project is not available for download, but you may build a tool from it yourself as an exercise.

## Room for Improvement


## Conclusion

# Conclusions

Next up, how to use D/Invoke to use exported functions from memory-mapped unmanaged DLLs... entirely from memory. Completely bypasses API Hooking and enables using DLLs reflectively.
