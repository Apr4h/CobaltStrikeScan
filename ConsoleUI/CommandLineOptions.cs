using CommandLine;


namespace ConsoleUI
{
    class CommandLineOptions
    {
        [Option('a', "all-processes", HelpText = "Scan all processes for Cobalt Strike beacons")]
        public bool AllProcesses { get; set; }

        [Option('d', "directory-scan", HelpText = "Scan all process/memory dump files in a directory for Cobalt Strike beacons")]
        public string Directory { get; set; }

        [Option('f', "scan-file", HelpText = "Scan a process/memory dump for Cobalt Strike beacons")]
        public string File { get; set; }

        [Option('i', "injected-threads", HelpText = "Scan running (64-bit) processes for injected threads (won't scan for Cobalt Strike beacons)")]
        public bool InjectedThreads { get; set; }

        [Option('p', "scan-processes", HelpText = "Scan running processes for injected threads and Cobalt Strike beacons")]
        public bool Processes { get; set; }

        [Option('v', "verbose", HelpText = "Write verbose output")]
        public bool Verbose { get; set; }

        [Option('w', "write-process-memory", HelpText = "Write process memory to file when injected threads are detected")]
        public bool WriteProcessMemory { get; set; }

        [Option('h', "help", HelpText = "Display Help Message")]
        public bool Help { get; set; }


        public CommandLineOptions()
        {
            AllProcesses = false;
            Processes = false;
            InjectedThreads = false;
            Help = false;
            WriteProcessMemory = false;
            Verbose = false;
        }

        public bool CheckIfNoArgs()
        {
            if (Processes.Equals(false) && File.Equals(false) && InjectedThreads.Equals(false) 
                && Help.Equals(false) && AllProcesses.Equals(false) && Directory.Equals(false))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
