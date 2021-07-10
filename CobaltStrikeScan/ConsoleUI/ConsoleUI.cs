using CobaltStrikeConfigParser;
using GetInjectedThreads;
using CommandLine;
using System;
using System.IO;
using System.Collections.Generic;
using static CobaltStrikeConfigParser.CobaltStrikeScan;
using System.Diagnostics;
using System.Security.Principal;
using CommandLine.Text;

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
                if (!IsUserAdministrator())
                {
                    OutputMessageToConsole(LogLevel.Error, "Not running as Administrator. Admin privileges required for '-p' option\n");
                    DisplayHelpText(result);
                }
                OutputMessageToConsole(LogLevel.Info, "Scanning processes for Cobalt Strike Beacons...");
                GetBeaconsFromAllProcesses();
            }
            // Check if file AND directory options were supplied - display error message and exit
            else if (!string.IsNullOrEmpty(opts.File) && !string.IsNullOrEmpty(opts.Directory))
            {
                OutputMessageToConsole(LogLevel.Error, "Error - Can't supply -f and -d options together.\n");
                DisplayHelpText(result);
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
                GetBeaconsFromInjectedThreads(opts);
            }
            else if (opts.Help)
            {
                DisplayHelpText(result);
            }
        }

        private static void GetBeaconsFromAllProcesses()
        {
            List<Beacon> beacons = new List<Beacon>();
            // foreach process, get process memory bytes
            foreach (Process process in Process.GetProcesses())
            {
                if (process.Id == 4 || process.Id == 0)
                    continue;

                try
                {
                    if (opts.Verbose)
                        OutputMessageToConsole(LogLevel.Info, $"Scanning Process: {process.ProcessName} {process.Id}");

                    byte[] processBytes = GetInjectedThreads.GetInjectedThreads.GetProcessMemoryBytes(process.Handle);

                    List<BeaconMatch> beaconMatches = YaraScanBytes(processBytes);

                    if (beaconMatches.Count > 0)
                    {
                        foreach (BeaconMatch match in beaconMatches)
                        {
                            OutputMessageToConsole(LogLevel.Success, $"Found Cobalt Strike beacon in process: {process.ProcessName} {process.Id}");
                            beacons.Add(GetBeaconFromYaraScan(match, processBytes));

                            if (opts.WriteProcessMemory)
                            {
                                WriteProcessBytesToFile(process, processBytes);
                            }
                        }
                    }
                }
                catch (System.ComponentModel.Win32Exception) { }
                catch (System.InvalidOperationException) { }
                // Thrown when GetProcessMemoryBytes tries to read a memory stream that is too large
                catch (System.IO.IOException) { }
                catch (OverflowException) { }
            }


            // Remove duplicate beacon objects to reduce output
            var uniqueBeacons = new HashSet<Beacon>();
            foreach (Beacon beacon in beacons)
            {
                if (!uniqueBeacons.Contains(beacon))
                    uniqueBeacons.Add(beacon);
            }

            if (uniqueBeacons.Count > 0)
            {
                foreach (Beacon beacon in uniqueBeacons)
                {
                    if (beacon.isValidBeacon())
                    {
                        OutputMessageToConsole(LogLevel.Success, $"Cobalt Strike Beacon Configuration\n");
                        beacon.OutputToConsole();
                    }
                }
            }
            else
            {
                OutputMessageToConsole(LogLevel.Info, "Didn't find Cobalt Strike beacon in processes")
;            }

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

        public static void WriteProcessBytesToFile (Process process, byte[] processBytes)
        {
            if (processBytes.Length > 0)
            {
                OutputMessageToConsole(LogLevel.Info, $"\tDumping RWX and RW memory for process: {process.ProcessName} {process.Id}");

                string writeTime = DateTime.Now.ToString("yyyyddMM-HHmmss");
                string fileName = $"{writeTime}-proc{process.Id}.dmp";

                File.WriteAllBytes(fileName, processBytes);
                OutputMessageToConsole(LogLevel.Success, $"\tWrote process bytes to file: {fileName}");
            }
        }

        public static bool IsUserAdministrator()
        {
            bool isAdmin;
            WindowsIdentity user = null;
            try
            {
                user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception)
            {
                isAdmin = false;
            }
            finally
            {
                if (user != null)
                    user.Dispose();
            }
            return isAdmin;
        }

        private static void DisplayHelpText(ParserResult<CommandLineOptions> result)
        {
            Console.WriteLine(HelpText.AutoBuild(result, h => h, e => e));
        }
    }
}
