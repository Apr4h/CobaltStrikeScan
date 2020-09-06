using GetInjectedThreads.Yara;
using libyaraNET;
using System;
using System.Collections.Generic;
using System.Text;


namespace GetInjectedThreads
{
    public static class CobaltStrikeScan
    {
        public static string v3 = "$config_v3";
        public static string v4 = "$config_v4";

        /// <summary>
        /// Perform YARA scan on process memory to detect meterpreter or Cobalt Strike payloads.
        /// </summary>
        /// <param name="processBytes">Byte array of target process to be scanned</param>
        public static Dictionary<string, ulong> YaraScanBytes(byte[] processBytes)
        {
            Dictionary<string, ulong> beaconScanMatches = new Dictionary<string, ulong>();

            using (var ctx = new YaraContext())
            {
                Rules rules = null;

                try
                {
                    using (Compiler compiler = new Compiler())
                    {
                        // Retrieve YARA rules from YaraRules static class and compile them for scanning
                        foreach (string rule in YaraRules.meterpreterRules)
                        {
                            compiler.AddRuleString(rule);
                        }

                        compiler.AddRuleString(YaraRules.cobaltStrikeRule);

                        rules = compiler.GetRules();
                    }

                    // Perform scan on process memory byte[]
                    Scanner scanner = new Scanner();
                    var results = scanner.ScanMemory(processBytes, rules);

                    // Check for rule matches in process bytes
                    foreach (ScanResult result in results)
                    {
                        if (result.MatchingRule.Identifier.Contains("CobaltStrike"))
                        {
                            // Get Version 3 match - find the first occurrence of the config string
                            if (result.Matches.ContainsKey(v3))
                            {
                                beaconScanMatches.Add(v3, result.Matches[v3][0].Offset);
                            }

                            // Get Version 4 match
                            if (result.Matches.ContainsKey(v4))
                            {
                                beaconScanMatches.Add(v4, result.Matches[v4][0].Offset);
                            }
                        }
                    }
                }
                finally
                {
                    if (rules != null) rules.Dispose();
                }
                return beaconScanMatches;
            }
        }

        public static Dictionary<string, ulong> YaraScanFile(string fileName)
        {

            Dictionary<string, ulong> beaconScanMatches = new Dictionary<string, ulong>();

            using (var ctx = new YaraContext())
            {
                Rules rules = null;

                try
                {
                    using (Compiler compiler = new Compiler())
                    {
                        // Retrieve YARA rules from YaraRules static class and compile them for scanning
                        foreach (string rule in YaraRules.meterpreterRules)
                        {
                            compiler.AddRuleString(rule);
                        }

                        compiler.AddRuleString(YaraRules.cobaltStrikeRule);

                        rules = compiler.GetRules();
                    }

                    // Scanner and ScanResults do not need to be disposed.
                    var scanner = new Scanner();
                    var results = scanner.ScanFile(fileName, rules);

                    foreach (ScanResult result in results)
                    {
                        if (result.MatchingRule.Identifier.Contains("CobaltStrike"))
                        {
                            // Get Version 3 match - find the first occurrence of the config string
                            if (result.Matches.ContainsKey(v3))
                            {
                                beaconScanMatches.Add(v3, result.Matches[v3][0].Offset);
                            }

                            // Get Version 4 match
                            if (result.Matches.ContainsKey(v4))
                            {
                                beaconScanMatches.Add(v4, result.Matches[v4][0].Offset);
                            }
                        }
                    }
                }
                finally
                {
                    // Rules and Compiler objects must be disposed.
                    if (rules != null) rules.Dispose();
                }

                return beaconScanMatches;
            }
        }


        private static void GetMeterpreterConfig(byte[] processBytes, ulong c2BlockOffset)
        {
            Console.WriteLine("Retrieving Meterpreter C2...");

            // C2 information starts 42 bytes after beginning of C2 block
            byte[] tmp = new byte[512];
            Buffer.BlockCopy(processBytes, ((int)c2BlockOffset + 42), tmp, 0, 512);

            // Remove null bytes from unicode strings
            string c2String = Encoding.UTF8.GetString(tmp).Replace("\0", string.Empty);
            Console.WriteLine(c2String);
        }
    }
}