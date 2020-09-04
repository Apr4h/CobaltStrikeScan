using CobaltStrikeConfigParser;
using GetInjectedThreads;
using CommandLine;
using System;
using System.IO;
using System.Collections.Generic;

namespace ConsoleUI
{
    class Program
    {
        static void Main(string[] args)
        {
            //Parse command line arguments
            CommandLineOptions opts = new CommandLineOptions();
            var parser = new Parser(with => with.HelpWriter = null);
            var result = parser.ParseArguments<CommandLineOptions>(args).WithParsed(parsed => opts = parsed);
            parser.Dispose();

            // Option Processes -p
            if (opts.Processes)
            {
                Console.WriteLine("Scanning processes for injected threads");

                List<InjectedThread> injectedThreads = GetInjectedThreads.GetInjectedThreads.InjectedThreads();

                foreach (InjectedThread injectedThread in injectedThreads)
                {
                    // Output Thread details to console
                    OutputInjectedThreadToConsole(injectedThread, opts.Verbose);


                    // Check if option set for dumping process memory
                    if (opts.Dump)
                    {
                        injectedThread.WriteBytesToFile();
                    }

                    // Scan process memory for injected thread
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Scanning injected thread for CobaltStrike beacon");
                    Console.ResetColor();

                    Dictionary<string, ulong> beaconMatchOffsets = CobaltStrikeScan.YaraScanBytes(injectedThread.ProcessBytes);

                    if (beaconMatchOffsets.Count > 0)
                    {
                        Beacon beacon = GetBeaconFromYaraScan(beaconMatchOffsets, injectedThread.ProcessBytes);

                        if (beacon != null)
                        {
                            beacon.OutputToConsole();
                        }
                    }
                    else { Console.WriteLine("Couldn't find CobaltStrike beacon in injected thread"); }
                }
            }

            // User supplied File option -f
            else if (!string.IsNullOrEmpty(opts.File))
            {
                if (File.Exists(opts.File))
                {
                    Dictionary<string, ulong> beaconMatchOffsets = CobaltStrikeScan.YaraScanFile(opts.File);

                    if (beaconMatchOffsets.Count > 0)
                    {
                        byte[] fileBytes = File.ReadAllBytes(opts.File);
                        Beacon beacon = GetBeaconFromYaraScan(beaconMatchOffsets, fileBytes);

                        if (beacon != null)
                        {
                            beacon.OutputToConsole();
                        }
                    }
                    else { Console.WriteLine("Couldn't find CobaltStrike beacon in file"); }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"File doesn't exist: {opts.File}\nExiting...");
                    Console.ResetColor();
                    System.Environment.Exit(1);
                }
            }
            else if (opts.InjectedThreads)
            {
                Console.WriteLine("Scanning processes for injected threads");

                List<InjectedThread> injectedThreads = GetInjectedThreads.GetInjectedThreads.InjectedThreads();

                foreach (InjectedThread injectedThread in injectedThreads)
                {
                    // Output Thread details to console
                    OutputInjectedThreadToConsole(injectedThread, opts.Verbose);


                    // Check if option set for dumping process memory
                    if (opts.Dump)
                    {
                        injectedThread.WriteBytesToFile();
                    }
                }
            }
        }

        private static void OutputInjectedThreadToConsole(InjectedThread injectedThread, bool verbose)
        {
            if (verbose)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Found injected thread");
                Console.ResetColor();
                injectedThread.OutputToConsole();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Found injected thread\n" +
                    $"\tProcess:\t{injectedThread.ProcessName}\n" +
                    $"\tPID:\t\t{injectedThread.ProcessID}\n" +
                    $"\tTID:\t\t{injectedThread.ThreadId}");
                Console.ResetColor();
            }
        }

        private static Beacon GetBeaconFromYaraScan(Dictionary<string, ulong> beaconMatchOffsets, byte[] bytes)
        {
            int version = 0;
            ulong offset = 0;

            if (beaconMatchOffsets.ContainsKey(CobaltStrikeScan.v3))
            {
                version = 3;
                offset = beaconMatchOffsets[CobaltStrikeScan.v3];
            }
            else if (beaconMatchOffsets.ContainsKey(CobaltStrikeScan.v4))
            {
                version = 4;
                offset = beaconMatchOffsets[CobaltStrikeScan.v4];
            }

            if (offset != 0)
            {
                Beacon beacon = new Beacon(bytes, offset, version);
                return beacon;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Yara scan found no matches for CobaltStrike payload");
                Console.ResetColor();
                return null;
            }
        }
    }
}
