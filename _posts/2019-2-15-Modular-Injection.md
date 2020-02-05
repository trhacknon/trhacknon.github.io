--
layout: post
title: Enabling Covert Operations - 1: Modular Process Injection API
---

*TLDR: How to dynamically invoke unmanaged code from memory or disk while avoiding API Hooking and suspicious imports, as well as an example that performs remote shellcode injection without Pinvoking suspicious API calls.*

# Dynamic Invocation - D/Invoke

Over the past few months, myself and b33f (@FuzzySecurity, Ruben Boonen) have quitely been adding an API to SharpSploit that helps you use unmanaged code from C# while avoiding suspicious P/Invokes. Rather than statically importing API calls with PInvoke, you may use Dynamic Invocation (I call it DInvoke) to load the DLL at runtime and call the function using a pointer to its location in memory. This avoids detections that look for imports of suspicious API calls via the Import Address Table in the .NET Assembly's PE headers. Additionally, it lets you call arbitrary unmanaged code from memory (while passing parameters on the stack), allowing you to bypass API hooking in a variety of ways. Overall. DInvoke is intended to be a direct replacement for PInvoke that gives offensive tool developers great flexibility in how they can access and invoke unmanaged code.
