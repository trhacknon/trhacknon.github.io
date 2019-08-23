---
layout: post
title: Donut v0.9.2 "Bear Claw" - JScript/VBScript/XSL/PE Shellcode, Python Bindings, and Cursing Microsoft
---

*TLDR: Version v0.9.2 "Bear Claw" of Donut has been released, including shellcode generated from many new types of payloads (JScript/VBScript/XSL and unmanaged DLL/PEs), and Python bindings that allow dynamic shellcode generation. Also, frustrated ranting about the MSVC compiler.*

# Introduction

In case you are unaware, [Donut](https://github.com/TheWover/donut "Donut") is a shellcode generation tool created to generate native shellcode payloads from .NET Assemblies. This shellcode may be used to inject the Assembly into arbitrary Windows processes. Given an arbitrary .NET Assembly, parameters, and an entry point (such as Program.Main), it produces position-independent shellcode that loads it from memory. 

Today, we are releasing a version that adds the capability to generate shellcode from other types of payloads. It also includes (long awaited) Python bindings, a new option, and many small miscellaneous improvements.

# Module Types

If you have wondered why we have not yet release v1.0, it is because we went down a rabbit hole. 

![_config.yml]({{ site.baseurl }}/images/Bear_Claw/rabbit.gif)

We realized that, fundamentally, Donut is not just a tool for generating shellcode from .NET Assemblies but can also be used as a framework for generating shellcode from arbitrary payload types. It is composed of the following elements:

* N # of loaders for specific payload types.
* `Payload.c`, which dynamically determines the payload type, loads it with the appropriate loader logic, and performs other functionalities such as decrypting the payload, running bypasses, and cleaning up memory.
* `Exe2h.c`, which converts payload.exe into Position Indpendant Code.
* `Donut.c`, the generator that transforms your payload into a Donut Module (your payload, and everything about it), creates a Donut Instance (an encrypted data structure that is the unit of execution for the Donut loader), and the PIC of `Payload.exe` with a Donut Config (tells the loader where to find the Instance) in order to produce the final shellcode.

To demonstrate the capabilities of this framework, we added several new Module types. All of them are types of payloads that enable similar tradecraft to generating shellcode from .NET Assemblies. At this time, we do not plan on adding additional module types to Donut. Those included in this release are sufficient to demonstrate the potential of the framework. With the examples and documentation that we have provided, you should have everything that you need to integrate a new loader and generate shellcode from your favorite type of payload. However, I leave open the possibility that we may go down additional rabbit holes in the future. :-) 

## VBScript/JScript (IActiveScript)

If you would like to learn more about how this works, you can read [the related blog post](https://modexp.wordpress.com/2019/07/21/inmem-exec-script/ "Shellcode: In-Memory Execution of JavaScript, VBScript, JScript and XSL") by Odzhan.

## XSL (Microsoft.XMLDom)

XSL files are XML files that can contain executable scripts. Theoretically, they are supposed to be used to transform the representation of data in XML. Microsoft built many tools and utilities for executing XSLT (XSL Transforms) into the Windows OS. Practically, however, they are mostly used as payloads by [malware authors](https://attack.mitre.org/techniques/T1220/). Perhaps the most well-known example is the now-patched [Squiblytwo](http://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html) Application Whitelisting Bypass that could execute remotely-hosted code from memory. 

The `Microsoft.XMLDOM` COM object allows for XSL transformation. It can either execute XSL [from disk or from memory](https://twitter.com/TheRealWover/status/1137382984418516992), containing JScript, VBScript, or C#. For v0.9.2 of Donut, we have created a module type that utilizes this COM object to load and execute XSL files from memory. Anything script that can normally execute through that COM object should be viable as a payload for Donut. _Please note, there are slight differences in how `Microsoft.XMLDOM` and WMIC.exe transform XSL that I have not fully explored._ If you would like to learn more about how this works, you can read [the related blog post](https://modexp.wordpress.com/2019/07/21/inmem-exec-script/ "Shellcode: In-Memory Execution of JavaScript, VBScript, JScript and XSL") by Odzhan.

I feel that I must bring up the question: Is this useful? Honestly, I'm not sure that it is. But it was easy and we got it working before the `IActiveScript` loader, so why throw out the functionality? If for some strange reason you DO want to execute XSL files through shellcode, then that is now a thing that you can do. You strange, strange person.

## Unmanaged DLLs / EXEs

[an article](https://modexp.wordpress.com/2019/06/24/inmem-exec-dll/ "Shellcode: In-Memory Execution of DLL")

# Donut API

Finalized the API. Should make it easier to add 

## Command Changes

* Option to not execute if the bypasses fail for any reason. OpSec for if they block you from disabling AMSI.

# Python Bindings

Demonstrating this API is a new Python binding for Donut written by Marcello Salvati ([byt3bl33der](https://twitter.com/byt3bl33d3r)).

# Cursing Microsoft

Overly helpful optimization. Had to figure out how trick it to use our stub functions.

Also, no more compatability with older versions because they broke stuff.

# Conclusion

What's next?

Taking a bit of a break until September October. Both Odzhan and I are working on seperate process injection libraries. His will be an awesome library of techniques. Mine will be a small set of implementations for SharpSploit that are designed to be as reliable, safe, and flexible as possible.
