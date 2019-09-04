---
layout: post
title: Donut v0.9.2 "Bear Claw" - JScript/VBScript/XSL/PE Shellcode and Python Bindings
---

*TLDR: Version v0.9.2 "Bear Claw" of Donut has been released, including shellcode generation from many new types of payloads (JScript/VBScript/XSL and unmanaged DLL/PEs), and Python bindings for dynamic shellcode generation.*

# Introduction

[Donut](https://github.com/TheWover/donut "Donut") is a shellcode generation tool created to generate native shellcode payloads from .NET Assemblies. This shellcode may be used to inject the Assembly into arbitrary Windows processes. Given an arbitrary .NET Assembly, parameters, and an entry point (such as `Program.Main`), it produces position-independent shellcode that loads the Assembly from memory. 

Today, we are releasing a version that adds the capability to generate shellcode from other types of payloads. It also includes (long awaited) Python bindings, a new safety option, and many small miscellaneous improvements.

# Module Types

If you have wondered why we have not yet release v1.0, it is because we went down a rabbit hole. 

![_config.yml]({{ site.baseurl }}/images/Bear_Claw/rabbit.gif)

We realized that, fundamentally, Donut is not just a tool for generating shellcode from .NET Assemblies but it can also be used as a framework for generating shellcode from arbitrary payload types. It is composed of the following elements:

* N # of loaders for specific payload types.
* `Payload.c`, which dynamically determines the payload type, loads it with the appropriate loader logic, and performs other functionalities such as decrypting the payload, running bypasses, and cleaning up memory.
* `Exe2h.c`, which extracts code from the `.text` section of `payload.exe` and saves it to a C array to be used in building the final PIC.
* `Donut.c`, the generator that transforms your payload into a Donut Module (your payload, and everything about it), creates a Donut Instance (an encrypted data structure that is the unit of execution for the Donut loader), and the PIC of `Payload.exe` with a Donut Config (tells the loader where to find the Instance) in order to produce the final shellcode.

To demonstrate the capabilities of this framework, we added several new Module types. All of them are types of payloads that enable similar tradecraft to generating shellcode from .NET Assemblies. At this time, we do not plan on adding additional module types to Donut. Those included in this release are sufficient to demonstrate the potential of the framework. With the examples and documentation that we have provided, you should have everything that you need to integrate a new loader and generate shellcode from your favorite type of payload. However, I leave open the possibility that we may go down additional rabbit holes in the future. :-) 

## VBScript/JScript (IActiveScript)

*TODO: Add an image and example of this!*

In ancient eras (before PowerShell) there was Visual Basic. Designed as an object-oriented scripting language for Windows operating systems, it became a universal tool for administrators seeking to avoid the hell that is Batch scripting. People liked Visual Basic. They liked it waaaaay toooooo muuuuuch. So Microsoft integrated it into everything. *everything*. And they made variants of it. *so many variants*. One of those variants was VBScript, which used COM to access and manage many components of the operating system. As with anything useful for admins, it was quickly adopted by malware authors. Recently, it has regained popularity in offensive tooling due to the amount of ways it can be loaded from memory or through application whitelisting bypasses.

Its better-bred cousin is JScript, the bastard child of JavaScript, COM, and .NET. Like VBScript, it also has free reign of the COM APIs, is sort of interoperable with .NET, and can be loaded from memory. Microsoft created it to act as either a web scripting language (for Internet Explorer) or client-side scripting language for system administrators. Shockingly, malware authors decided to abuse it for browser breakouts and RATs.

Both languages have access to the Windows Scripting Host, a system that allows them access to operating system features like running shell commands. Between their access to managed and unmanaged APIs, COM, and tons of other useful/dangerous tools, they have each provided powerful platforms for obtaining initial access and running post-exploitation scripts. This has made them weapons of choice in many payload types like SCT, XML, and HTA through a [variety](https://attack.mitre.org/techniques/T1117/ "regsvr32") of [execution](https://attack.mitre.org/techniques/T1127/ "MSBuild") [vectors](https://attack.mitre.org/techniques/T1170/ "MSHTA").

Both JScript and VBScript are based on a generic scripting framework called [ActiveScript](https://en.wikipedia.org/wiki/Active_Scripting) built on a combination of COM and OLE Automation. Developers could also create additional scripting languages through COM modules, leading to Active implementations of third-party languages like Perl and Python. The Active Script engine is exposed through the COM interface `IActiveScript`, which allows the user to execute arbitrary scripting code through any installed Active Script language module. We wrote a wrapper for it that allows you to load any ActiveScript-compatible scripting language from memory.

All this to say: you can now take your existing JScript/VBScript payloads and execute them through shellcode. We go ahead and disable AMSI for you, and ensure that Device Guard won't prevent dynamic code execution. You could even load a .NET Assembly by combining DotNetToJScript & Donut!!! (*Test this*)

If you would like to learn more about how this works, you can read [the related blog post](https://modexp.wordpress.com/2019/07/21/inmem-exec-script/ "Shellcode: In-Memory Execution of JavaScript, VBScript, JScript and XSL") by Odzhan.

## XSL (Microsoft.XMLDom)

XSL files are XML files that can contain executable scripts. Theoretically, they are supposed to be used to transform the representation of data in XML. Microsoft built many tools and utilities for executing XSLT (XSL Transforms) into the Windows OS. Practically, however, they are mostly used as payloads by [malware authors](https://attack.mitre.org/techniques/T1220/). Perhaps the most well-known example is the now-patched [Squiblytwo](http://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html) Application Whitelisting Bypass that could execute remotely-hosted code from memory. 

The `Microsoft.XMLDOM` COM object allows for XSL transformation. It can either execute XSL [from disk or from memory](https://twitter.com/TheRealWover/status/1137382984418516992), containing JScript, VBScript, or C#. For v0.9.2 of Donut, we have created a module type that utilizes this COM object to load and execute XSL files from memory. Any script that can normally execute through that COM object should be viable as a payload for Donut. _Please note, there are slight differences in how `Microsoft.XMLDOM` and WMIC.exe transform XSL that I have not fully explored._ If you would like to learn more about how this works, you can read [the related blog post](https://modexp.wordpress.com/2019/07/21/inmem-exec-script/ "Shellcode: In-Memory Execution of JavaScript, VBScript, JScript and XSL") by Odzhan.

*TODO: Add an image and example of this!*

I feel that I must bring up the question: Is this useful? Honestly, I'm not sure that it is. But it was relatively easy to get working, nobody else has done it before, and we finished it before the `IActiveScript` loader (which is probably more useful), so why throw out the functionality? If for some strange reason you DO want to execute XSL files through shellcode, then that is now a thing that you can do. You strange, strange person.

![_config.yml]({{ site.baseurl }}/images/Bear_Claw/strange.gif)

## Unmanaged DLLs / EXEs

If you are a more normal person, you may want to execute unmanaged DLLs and EXEs instead.

Using the standard format of Windows executables, unmanaged [PE files](https://blog.kowalczyk.info/articles/pefileformat.html) are a simple unit of execution for exploits and post-exploitation payloads. However, their severe disadvantage is that they are designed to be run from disk by the Windows loader. Modern offensive tradecraft hopes to presume that all payloads are run from memory, rather than from disk. As such, there is a long history of tool creators crafting various means by which to load PEs from memory. Some people convert them to shellcode, others write PE loaders, we have done both at the same time. We wrote a PE loader, that is itself converted to shellcode. Your PE is wrapped in an encrypted Donut Module and can be loaded from memory like any other Module type. 

By default, the PE loader will execute whatever the Entry Point of your executable is (as specified by the PE headers). For EXEs, that is the main entry point. For DLLs, that would be `DLLMain` with `DLL_PROCESS_ATTACH`. For DLLs, you may optionally specify an exported function and pass in parameters as strings.

*TODO: Add an image and example of this!*

If you would like to learn more about how this works, you can read [this blog post](https://modexp.wordpress.com/2019/06/24/inmem-exec-dll/ "Shellcode: In-Memory Execution of DLL") by Odzhan.

### Caution: Beyond Here Be Dragons

![_config.yml]({{ site.baseurl }}/images/Bear_Claw/Lenox_Globe_Dragons.png)

I must state a very important caveat for this PE Loader: *We run whatever code you tell us to run. Whether that code is reliable is up to you.*

There are inherant dangers to injecting PE files into processes. DLLs are usually not very dangerous, but EXEs are risky. If your EXE tries to use any Windows subsystem or exit the process, *it will do exactly that.* None of the safety mechanisms in .NET exist when executing unmanaged code. So, if you inject an EXE into a GUI process (one with existing windows) that was designed to be used as a console application and it therefore attempts to use the subsystems for console output, it may crash the process. The reverse is also true. Simply put, Your Mileage May Vary with injecting PE files. We cannot provide you with any protections or extra reliability when we execute your code. Generating the shellcode is up to us. Injecting it safely is up to you. :-) 

# Memory Permissions

An undocumented "feature" of previous Donut versions was that its shellcode only ran from `RWX` memory. If you attempted to execute it from `RX` memory then it would crash... as multiple people messaged me about. :-D We fixed that for Donut v0.9.2. You may now pretend that you are not as evil as you are.

# Donut API

We did not want to add additional wrappers or generators (Python, C#, etc.) for Donut until our API had been stabilized. At this point, we consider it stable enough to move forward with those plans. Many small fixes, improvements, and changes were made to the inner workings of Donut for v0.9.2. Too many to detail. Overall, the API and its internals have been cleaned up and should be more future-proof than before.

## Command Addition - Bypass Failure Handling

Other than adding new types of payloads, we added one small feature to Donut. A `-b` option that can prevent the payload from being loaded if the bypasses fail to execute for any reason. We do not know of any AV or EDR that currently prevents our bypasses. But if they fail for any reason then you can reduce the likelihood of detection by ensuring that your payload is not passed to AMSI. The full set of options are below.

```
 -b <level>           Bypass AMSI/WLDP : 1=skip, 2=abort on fail, 3=continue on fail.(default)
```

# Python Bindings

Demonstrating our API is a new Python 3 binding for Donut written by Marcello Salvati ([byt3bl33d3r](https://twitter.com/byt3bl33d3r)). It exposes Donut's `DonutCreate` API call to Python code, allowing for dynamic generation of Donut shellcode with all of the normal features. He also added support for PyPi, meaning that you can install Donut locally or from the PyPi repositories using pip3.

*TODO: Install examples*

![_config.yml]({{ site.baseurl }}/images/Bear_Claw/import_donut.PNG)

## Examples

Creating shellcode from JScript/VBScript.
```python
shellcode = donut.create(file=r"C:\\Tools\\Source\\Repos\\donut\\calc.js")
f = open("shellcode.bin", "wb")
f.write(shellcode)
f.close()
```

Creating shellcode from an XSL file that pops up a calculator.
```python
shellcode = donut.create(file=r"C:\\Tools\\Source\\Repos\\donut\\calc.xsl")
```

Creating shellcode from an unmanaged DLL. Invokes DLLMain.
```python
shellcode = donut.create(file=r"C:\Tools\Source\Repos\donut\payload\test\hello.dll")
```

Creating shellcode from an unmanaged DLL, using the exported function `DonutAPI`, and passing in 4 parameters.
```python
shellcode = donut.create(file=r"C:\Tools\Source\Repos\donut\payload\test\hello.dll", params = "hello1,hello2,hello3,hello4", method="DonutAPI")
```

And, of course, creating shellcode from a .NET Assembly, specifying many options.

```python
shellcode = donut.create(file=r"C:\Tools\Source\Repos\donut\DemoCreateProcess\bin\Release\ClassLibrary.dll", params="notepad.exe,calc.exe", cls="TestClass", method="RunProcess", arch=1, appdomain="TotallyLegit")
```

The full documentation for these Python bindings can be found in our `docs` [folder](https://github.com/TheWover/donut/blob/master/docs/2019-08-21-Python_Extension.md).

# MSVC Compatability

Due to recent changes in the MSVC compiler, we will only support 2019 and later versions of MSVC in future versions of Donut. Mingw support will remain the same. 

# Conclusion

What's next? In the short-term, we are taking a break from Donut until Octoberish. Both Odzhan and I are working on seperate process injection libraries. His will be an awesome library of techniques. Mine will be a small set of implementations for SharpSploit that are designed to be as reliable, safe, and flexible as possible. Afterwards, we will resume work towards v1.0 of Donut. 

# P.S.

I feel that I must note somewhere in this blog post: all of the hard work for this release of Donut was done by other people. :-) I have not had spare time to work on side projects recently, so have only contributed ideas, planning, and documentation to this version. If you are going to thank somebody for the hard work that went into this release, thank Odzhan or byt3bl33d3r. ;-) 
