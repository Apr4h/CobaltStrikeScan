﻿using CobaltStrikeConfigParser;
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
        public enum LogLevel
        {
            Info,
            Warn,
            Error,
            Success
        }

        public static CommandLineOptions opts = new CommandLineOptions();

        static void Main(string[] args)
        {
            //Parse command line arguments
            //CommandLineOptions opts = new CommandLineOptions();
            var result = Parser.Default.ParseArguments<CommandLineOptions>(args).WithParsed(parsed => opts = parsed);
            var title = new HeadingInfo("CobaltStrikeScan");

            // Option Processes -p
            if (opts.Processes)
            {
                GetBeaconsFromInjectedThreads(opts);
            }

            // Check if file AND directory options were supplied - display error message and exit
            if (!string.IsNullOrEmpty(opts.File) && !string.IsNullOrEmpty(opts.Directory))
            {
                OutputMessageToConsole(LogLevel.Error, "Error - Can't supply -f and -d options together.\n");
                DisplayHelpText(result);
                Environment.Exit(0);
            }

            // User supplied File option -f or Directory option -d
            else if (!string.IsNullOrEmpty(opts.File) || !string.IsNullOrEmpty(opts.Directory))
            {
                // "Scan single file" option
                if (!string.IsNullOrEmpty(opts.File))
                {
                    GetBeaconsFromFile(opts.File);
                }
                // "Scan a directory" option
                else if (!string.IsNullOrEmpty(opts.Directory))
                {
                    GetBeaconsFromDirectory(opts.Directory);
                }
                
            }
            else if (opts.InjectedThreads)
            {
                OutputMessageToConsole(LogLevel.Info, "Scanning processes for injected threads\n");

                List<InjectedThread> injectedThreads = GetInjectedThreads.GetInjectedThreads.InjectedThreads();

                foreach (InjectedThread injectedThread in injectedThreads)
                {
                    // Output Thread details to console
                    OutputInjectedThreadToConsole(injectedThread, opts.Verbose);

                    // Check if option set for dumping process memory
                    if (opts.WriteProcessMemory)
                    {
                        injectedThread.WriteBytesToFile();
                    }
                }
            }
            else if (opts.Help)
            {
                DisplayHelpText(result);
            }
            else
            {
                DisplayHelpText(result);
            }
        }

        private static void OutputInjectedThreadToConsole(InjectedThread injectedThread, bool verbose)
        {
            string format = "{0,-32} : {1}";

            if (verbose)
            {
                OutputMessageToConsole(LogLevel.Success, $"Found injected thread");
                injectedThread.OutputToConsole();
            }
            else
            {
                OutputMessageToConsole(LogLevel.Success, "Found injected thread");
                Console.WriteLine(format, "Process", injectedThread.ProcessName);
                Console.WriteLine(format, "Process ID", injectedThread.ProcessID);
                Console.WriteLine(format, "Thread ID", injectedThread.ThreadId);
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Get Cobalt Strike beacons from processes with evidence of injected threads. Outputs beacon configuration to the console.
        /// </summary>
        /// <param name="opts"></param>
        private static void GetBeaconsFromInjectedThreads(CommandLineOptions opts)
        {
            OutputMessageToConsole(LogLevel.Info, "Scanning processes for injected threads");
            List<Beacon> beacons = new List<Beacon>();
            List<InjectedThread> injectedThreads = GetInjectedThreads.GetInjectedThreads.InjectedThreads();

            foreach (InjectedThread injectedThread in injectedThreads)
            {
                // Output Thread details to console
                OutputInjectedThreadToConsole(injectedThread, opts.Verbose);

                // Check if option set for dumping process memory
                if (opts.WriteProcessMemory)
                {
                    injectedThread.WriteBytesToFile();
                }

                // Scan process memory for injected thread
                OutputMessageToConsole(LogLevel.Info, "Scanning injected thread for CobaltStrike beacon");

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
                            if (beacon.isValidBeacon())
                            {
                                OutputMessageToConsole(LogLevel.Success, $"Cobalt Strike Beacon Configuration\n");
                                beacon.OutputToConsole();
                            }
                        }
                    }
                    else
                        OutputBeaconNotFoundMessage();
                }
                else { OutputBeaconNotFoundMessage(); }
            }
        }

        /// <summary>
        /// Scan all files in a directory for Cobalt Strike beacons and output their configuration to the console.
        /// </summary>
        /// <param name="directory"></param>
        private static void GetBeaconsFromDirectory(string directory)
        {
            OutputMessageToConsole(LogLevel.Info, $"Scanning files in directory: {directory}\n");
            if (Directory.Exists(directory))
            {
                IEnumerable<string> files = Directory.EnumerateFiles(directory);

                foreach (string fileName in files)
                {
                    GetBeaconsFromFile(fileName);
                }                   
            }
            else
            {
                OutputMessageToConsole(LogLevel.Error, $"Directory {directory} does not exist\n");
            }
        }

        /// <summary>
        /// Get Cobalt Strike Configurations from a file and output their contents to the console . 
        /// </summary>
        /// <param name="fileName">Name of memory/dump file to be scanned for Cobalt Strike beacons</param>
        private static void GetBeaconsFromFile(string fileName)
        {
            OutputMessageToConsole(LogLevel.Info, $"Scanning file: {fileName}");
            List<Beacon> beacons = new List<Beacon>();

            if (File.Exists(fileName))
            {
                // Check the size of the file. If > 500MB, and notify that scanning will take time
                var fileSize = new FileInfo(fileName).Length;
                if (fileSize > Int32.MaxValue)
                {
                    OutputMessageToConsole(LogLevel.Warn, $"\tFile is large: {fileSize / (1024 * 1024)} MB. Scanning will be slow.");
                }

                // Yara scan the file and return any matches
                List<BeaconMatch> beaconMatches = CobaltStrikeScan.YaraScanFile(fileName, opts.Verbose);

                // Extract config bytes at each match offset and parse the beacon config from them
                if (beaconMatches.Count > 0)
                {
                    if (opts.Verbose)
                    {
                        OutputMessageToConsole(LogLevel.Info, $"\t{beaconMatches.Count} Signature(s) detected in file. Attempting to extract and parse config...\n");
                    }
                    foreach (BeaconMatch match in beaconMatches)
                    {
                        try
                        {
                            byte[] beaconConfigBytes = new byte[4096];
                            // Get a byte array from the offset of the file with beacon matches to avoid cases
                            // where the file is too big to read in to a File object
                            using (FileStream fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read))
                            {
                                fileStream.Seek((long)match.Offset, SeekOrigin.Begin);
                                fileStream.Read(beaconConfigBytes, 0, 4096);
                            }
                            match.Offset = 0;
                            beacons.Add(GetBeaconFromYaraScan(match, beaconConfigBytes));
                        }
                        catch (System.IO.IOException)
                        {
                            /* 
                            if (opts.Verbose)
                            {
                                OutputMessageToConsole(LogLevel.Error, $"Error extracting signatured data from file at offset: {match.Offset}");
                            }
                            */
                        }
                    }

                    if (beacons.Count > 0)
                    {
                        foreach (Beacon beacon in beacons)
                        {
                            if (beacon.isValidBeacon())
                            {
                                OutputMessageToConsole(LogLevel.Success, $"Cobalt Strike Beacon Configuration\n");
                                beacon.OutputToConsole();
                            }
                        }
                    }
                    else
                        OutputBeaconNotFoundMessage();
                }
                else { OutputBeaconNotFoundMessage(); }
            }
            else
            {
                OutputMessageToConsole(LogLevel.Error, $"File doesn't exist: {fileName}\nExiting...");
                System.Environment.Exit(1);
            }        
        }

        private static void OutputBeaconNotFoundMessage()
        {
            OutputMessageToConsole(LogLevel.Error, "Couldn't find Cobalt Strike beacon in file");
        }

        public static void OutputMessageToConsole(LogLevel logLevel, string message)
        {
            switch (logLevel)
            {
                case LogLevel.Info:
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    break;
                case LogLevel.Warn:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    break;
                case LogLevel.Error:
                    Console.ForegroundColor = ConsoleColor.Red;
                    break;
                case LogLevel.Success:
                    Console.ForegroundColor = ConsoleColor.Green;
                    break;
                default:
                    Console.ResetColor();
                    break;
            }
            Console.WriteLine(message);
            Console.ResetColor();
        }

        private static void DisplayHelpText(ParserResult<CommandLineOptions> result)
        {
            Console.WriteLine(HelpText.AutoBuild(result, h => h, e => e));
        }
    }
}
