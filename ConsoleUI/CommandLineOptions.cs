using CommandLine;


namespace ConsoleUI
{
    class CommandLineOptions
    {

        [Option('d', "dump-processes", HelpText = "Dump process memory to file when injected threads are detected")]
        public bool Dump { get; set; }

        [Option('f', "scan-file", HelpText = "Scan a file/process dump for CobaltStrike beacons (won't work on stager/dropper executables")]
        public string File { get; set; }

        [Option('i', "injected-threads", HelpText = "Scan running (64-bit) processes for injected threads (won't scan for CobaltStrike beacons)")]
        public bool InjectedThreads { get; set; }

        [Option('p', "scan-processes", HelpText = "Scan running processes for injected threads and CobaltStrike beacons")]
        public bool Processes { get; set; }

        [Option('v', "verbose", HelpText = "Write verbose output")]
        public bool Verbose { get; set; }

        [Option('h', "help", HelpText = "Display Help Message")]
        public bool Help { get; set; }


        public CommandLineOptions()
        {
            Processes = false;
            InjectedThreads = false;
            Help = false;
            Dump = false;
            Verbose = false;
        }

        public bool CheckIfNoArgs()
        {
            if (Processes.Equals(false) && File.Equals(false) && InjectedThreads.Equals(false) && Help.Equals(false))
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
