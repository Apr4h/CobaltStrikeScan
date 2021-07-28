# CobaltStrikeScan
Scan files or process memory for Cobalt Strike beacons and parse their configuration.

CobaltStrikeScan scans Windows process memory for evidence of DLL injection (classic or reflective injection) and/or performs a YARA scan on the target process' memory for Cobalt Strike v3 and v4 beacon signatures. 

Alternatively, CobaltStrikeScan can perform the same YARA scan on a file supplied by absolute or relative path as a command-line argument.

If a Cobalt Strike beacon is detected in the file or process, the beacon's configuration will be parsed and displayed to the console.

## Cloning This Repo
CobaltStrikeScan contains [GetInjectedThreads](https://github.com/Apr4h/GetInjectedThreads) as a submodule. Ensure you use `git clone --recursive https://github.com/Apr4h/CobaltStrikeScan.git` when cloning CobaltStrikeScan so that the submodule's code is also downloaded/cloned.

## Building the Solution
Costura.Fody is configured to embed CommandLine.dll and libyara.NET.dll in the compiled CobaltStrikeScan.exe assembly. CobaltStrikeScan.exe should then serve as a static, portable version of CobaltStrikeScan. For this to occur, ensure that the "Active Solution Platform" is set to x64 when building.

## Acknowledgements
This project is inspired by the following research / articles:
- [SpecterOps - Defenders Think in Graphs Too](https://posts.specterops.io/defenders-think-in-graphs-too-part-1-572524c71e91)
- [JPCert - Volatility Plugin for Detecting Cobalt Strike](https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html)
- [SentinelLabs - The Anatomy of an APT Attack and CobaltStrike Beacon’s Encoded Configuration](https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration)
- Neo23x0's [Signature Base](https://github.com/Neo23x0/signature-base) for high-quality YARA signatures used to detect Cobalt Strike's encoded configuration block.

## Requirements
- 64-bit Windows OS
- .NET Framework 4.6
- Administrator or SeDebugPrivilege is required to scan process memory for injected threads

## Usage
```
  -d, --directory-scan          Scan all process/memory dump files in a directory for Cobalt Strike beacons

  -f, --scan-file               Scan a process/memory dump for Cobalt Strike beacons

  -i, --injected-threads        Scan running (64-bit) processes for injected threads and Cobalt Strike beacons

  -p, --scan-processes          Scan running processes for Cobalt Strike beacons

  -v, --verbose                 Write verbose output

  -w, --write-process-memory    Write process memory to file when injected threads are detected

  -h, --help                    Display Help Message

  --help                        Display this help screen.

  --version                     Display version information.
```

## Example
![Image](./cobaltstrikescan_procdump_example.PNG)
