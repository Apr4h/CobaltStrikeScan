using CobaltStrikeConfigParser;
using GetInjectedThreads;
using CommandLine;
using CommandLine.Text;
using System;
using System.IO;
using System.Collections.Generic;
using static CobaltStrikeConfigParser.CobaltStrikeScan;

namespace ConsoleUI
{
    class Program
    {
        static void Main(string[] args)
        {
            List<Beacon> beacons = new List<Beacon>();

            //Parse command line arguments
            CommandLineOptions opts = new CommandLineOptions();
            var result = Parser.Default.ParseArguments<CommandLineOptions>(args).WithParsed(parsed => opts = parsed);
            var title = new HeadingInfo("CobaltStrikeScan");

            // Option Processes -p
            if (opts.Processes)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Scanning processes for injected threads");
                Console.ResetColor();

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

                    List<BeaconMatch> beaconMatches = CobaltStrikeScan.YaraScanBytes(injectedThread.ProcessBytes);

                    if (beaconMatches.Count > 0)
                    {
                        foreach (BeaconMatch match in beaconMatches)
                        {
                            beacons.Add(GetBeaconFromYaraScan(match, injectedThread.ProcessBytes));
                        }
                        
                        if (beacons.Count > 0)
                        {
                            foreach (Beacon beacon in beacons)
                            {
                                beacon.OutputToConsole();
                            }
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
                    // Check the size of the file. If > 500MB, and notify
                    var fileSize = new FileInfo(opts.File).Length;
                    if (fileSize > 524288000)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("File size > 500MB. Scanning may take some time...\n");
                        Console.ResetColor();
                    }

                    // Yara scan the file and return any matches
                    List<BeaconMatch> beaconMatches = CobaltStrikeScan.YaraScanFile(opts.File);

                    // Extract config bytes at each match offset and parse the beacon config from them
                    if (beaconMatches.Count > 0)
                    {
                        foreach (BeaconMatch match in beaconMatches)
                        {
                            byte[] beaconConfigBytes = new byte[4096];
                            // Get a byte array from the offset of the file with beacon matches to avoid cases
                            // where the file is too big to read in to a File object
                            using (FileStream fileStream = new FileStream(opts.File, FileMode.Open, FileAccess.Read))
                            {
                                fileStream.Seek((long)match.Offset, SeekOrigin.Begin);
                                fileStream.Read(beaconConfigBytes, 0, 4096);
                            }
                            match.Offset = 0;
                            beacons.Add(GetBeaconFromYaraScan(match, beaconConfigBytes));
                        }

                        if (beacons.Count > 0)
                        {
                            foreach (Beacon beacon in beacons)
                            {
                                beacon.OutputToConsole();
                            }
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
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Scanning processes for injected threads\n");
                Console.ResetColor();

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
            else if (opts.Help)
            {
                Console.WriteLine(HelpText.AutoBuild(result, h => h, e => e)); 
            }
            else
            {
                Console.WriteLine(HelpText.AutoBuild(result, h => h, e => e));
            }
        }

        private static void OutputInjectedThreadToConsole(InjectedThread injectedThread, bool verbose)
        {
            string format = "{0,-32} : {1}";

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
                Console.WriteLine($"Found injected thread");
                Console.ResetColor();
                Console.WriteLine(format, "Process", injectedThread.ProcessName);
                Console.WriteLine(format, "Process ID", injectedThread.ProcessID);
                Console.WriteLine(format, "Thread ID", injectedThread.ThreadId);
                Console.WriteLine();
            }
        }

        private static Beacon GetBeaconFromYaraScan(BeaconMatch match, byte[] bytes)
        { 
            List<Beacon> beacons = new List<Beacon>();


            if (match.Version == v3)
            {
                return new Beacon(bytes, match.Offset, 3);
            }
            else if (match.Version == v4)
            {
                return new Beacon(bytes, match.Offset, 4);
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
