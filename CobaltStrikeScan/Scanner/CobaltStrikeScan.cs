using CobaltStrikeConfigParser.Yara;
using libyaraNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CobaltStrikeConfigParser
{
    public static class CobaltStrikeScan
    {
        public static string v3 = "$config_v3";
        public static string v4 = "$config_v4";
        public static string decoded = "$config_decoded";

        public class BeaconMatch
        {
            public string Version { get; set; }
            public ulong Offset { get; set; }

            public BeaconMatch(string version, ulong offset)
            {
                Version = version;
                Offset = offset;
            }
        }

        /// <summary>
        /// Perform YARA scan on process memory to detect meterpreter or Cobalt Strike payloads.
        /// </summary>
        /// <param name="processBytes">Byte array of target process to be scanned</param>
        public static List<BeaconMatch> YaraScanBytes(byte[] processBytes)
        {
            List<BeaconMatch> beaconScanMatches = new List<BeaconMatch>();

            using (var ctx = new YaraContext())
            {
                Rules rules = null;

                try
                {
                    using (Compiler compiler = new Compiler())
                    {
                        // Retrieve YARA rules from YaraRules static class and compile them for scanning
                        /*
                        foreach (string rule in YaraRules.meterpreterRules)
                        {
                            compiler.AddRuleString(rule);
                        }
                        */

                        compiler.AddRuleString(YaraRules.cobaltStrikeRule);

                        rules = compiler.GetRules();
                    }

                    // Perform scan on process memory byte[]
                    Scanner scanner = new Scanner();
                    var results = scanner.ScanMemory(processBytes, rules);

                    beaconScanMatches = ParseScanResults(results);
                }
                finally
                {
                    if (rules != null) rules.Dispose();
                }
                return beaconScanMatches;
            }
        }

        public static List<BeaconMatch> YaraScanFile(string fileName, bool verbose)
        {

            List<BeaconMatch> beaconScanMatches = new List<BeaconMatch>();

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

                    List<ScanResult> results = new List<ScanResult>();

                    // If file size > 2GB, stream the file and use ScanMemory() on file chunks rather than reading the whole file via 
                    if (new FileInfo(fileName).Length < Int32.MaxValue)
                    {
                       results.AddRange(scanner.ScanFile(fileName, rules));
                    }
                    else
                    {
                        using (FileStream fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read))
                        {
                            // Parse the file in 200MB chunks
                            int chunkSize = 1024 * 1024 * 200;
                            byte[] chunk = new byte[chunkSize];
                            int bytesRead = 0;
                            long bytesToRead = fileStream.Length;

                            while (bytesToRead != 0)
                            {
                                int n = fileStream.Read(chunk, 0, chunkSize);

                                if (n == 0)
                                {
                                    break;
                                }

                                // Yara scan the file chunk and add any results to the list
                                var scanResults = scanner.ScanMemory(chunk, rules);

                                // Because the file is being scanned in chunks, match offsets are based on the start of the chunk. Need to add
                                // previous bytes read to the current match offsets
                                if (scanResults.Count > 0)
                                {
                                    foreach (ScanResult result in scanResults)
                                    {
                                        if (result.MatchingRule.Identifier.Contains("CobaltStrike"))
                                        {
                                            foreach (string key in result.Matches.Keys)
                                            {
                                                result.Matches[key][0].Offset += (ulong)bytesRead;
                                            }
                                            results.Add(result);
                                        }
                                    }
                                }

                                bytesRead += n;
                                bytesToRead -= n;
                                
                                // Shitty progress update
                                if (verbose && bytesRead > 0 && bytesRead <= fileStream.Length)
                                    Console.Write($"\r\tScanned {bytesRead} bytes of {fileStream.Length} byte file...");
                            }
                        }
                        if (verbose)
                            Console.WriteLine($"\r\tFinished scanning file: {fileName}\t\t\t");
                    }

                    beaconScanMatches = ParseScanResults(results);
                }
                finally
                {
                    // Rules and Compiler objects must be disposed.
                    if (rules != null) rules.Dispose();
                }

                return beaconScanMatches;
            }
        }

      
        private static List<BeaconMatch> ParseScanResults(List<ScanResult> results)
        {
            List<BeaconMatch> beaconScanMatches = new List<BeaconMatch>();
            // Check for rule matches in process bytes
            foreach (ScanResult result in results)
            {
                if (result.MatchingRule.Identifier.Contains("CobaltStrike"))
                {
                    foreach (KeyValuePair<string, List<Match>> item in result.Matches)
                    {
                        beaconScanMatches.Add(new BeaconMatch(item.Key, item.Value[0].Offset));
                    }
                }
            }

            return beaconScanMatches;
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