/*
 * Kirin-Tool — lock diagnostic (read-only).
 * See the project LICENSE for the terms that apply to this file.
 */

using Kirin_Tool.Models;
using Kirin_Tool.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Kirin_Tool.Services
{
    public sealed class OemInfoEntry
    {
        public int Offset { get; init; }
        public int Version { get; init; }
        public int Id { get; init; }
        public int Age { get; init; }
        public int DataLength { get; init; }
        public byte[] Data { get; init; } = Array.Empty<byte>();
    }

    public sealed class LockDiagnosticResult
    {
        public string ReportText { get; set; } = "";
        public string Summary { get; set; } = "";
    }

    /// <summary>
    /// Read-only diagnostic for the Huawei lock records.
    ///
    /// It dumps oeminfo, nvme and fastboot through the running (factory) fastboot,
    /// parses the OEM_INFO entries, verifies the USERLOCK HMAC of oeminfo id 0x5d
    /// with the USRKEY NV item, and compares the dumped fastboot image against the
    /// FASTBOOT block of an UPDATE.APP and/or a signed factory fastboot.img.
    ///
    /// No partition is written and no lock state is modified.
    /// </summary>
    public sealed class LockDiagnosticService
    {
        private const int OemInfoBlockSize = 0x400;
        private const int OemInfoDataOffset = 0x200;
        private static readonly byte[] OemInfoMagic = Encoding.ASCII.GetBytes("OEM_INFO");

        private readonly FastbootClient _fastbootClient;

        public LockDiagnosticService(FastbootClient fastbootClient)
        {
            _fastbootClient = fastbootClient;
        }

        public async Task<LockDiagnosticResult> RunAsync(
            string outputDirectory,
            string? baseUpdateAppPath,
            string? factoryFastbootPath,
            IProgress<string>? progress = null)
        {
            if (string.IsNullOrWhiteSpace(outputDirectory))
                throw new ArgumentException("Output directory is required.", nameof(outputDirectory));

            Directory.CreateDirectory(outputDirectory);

            var notes = new List<string>();
            var oemInfoEntries = new List<OemInfoEntry>();

            progress?.Report("Reading lock state...");
            string lockState = await TryReadStringAsync(
                () => _fastbootClient.OemCommandAsync("lock-state info", timeoutMinutes: 2),
                "oem lock-state info", notes);
            string bootInfo = await TryReadStringAsync(
                () => _fastbootClient.OemCommandAsync("get-bootinfo", timeoutMinutes: 2),
                "oem get-bootinfo", notes);
            string usrKeyRaw = await TryReadStringAsync(
                () => _fastbootClient.ReadNveVariable("USRKEY"),
                "getvar nve:USRKEY", notes);
            string usrKeyAltRaw = await TryReadStringAsync(
                () => _fastbootClient.ReadNveVariable("USER"),
                "getvar nve:USER", notes);
            string fblockRaw = await TryReadStringAsync(
                () => _fastbootClient.ReadNveVariable("FBLOCK"),
                "getvar nve:FBLOCK", notes);

            progress?.Report("Dumping oeminfo, nvme and fastboot (read-only)...");
            string oemInfoPath = Path.Combine(outputDirectory, "oeminfo.dump.img");
            string nvmePath = Path.Combine(outputDirectory, "nvme.dump.img");
            string fastbootPath = Path.Combine(outputDirectory, "fastboot.dump.img");

            var oemInfoDump = await TryDumpPartitionAsync("oeminfo", oemInfoPath, notes);
            var nvmeDump = await TryDumpPartitionAsync("nvme", nvmePath, notes);
            var fastbootDump = await TryDumpPartitionAsync("fastboot", fastbootPath, notes);

            byte[]? oemInfo = File.Exists(oemInfoPath) ? await File.ReadAllBytesAsync(oemInfoPath) : null;
            if (oemInfo != null)
            {
                oemInfoEntries = ParseOemInfo(oemInfo);
                if (oemInfoEntries.Count == 0)
                    notes.Add("No OEM_INFO blocks found in the oeminfo dump.");
            }

            var userLockEntry = LatestEntry(oemInfoEntries, 0x5d);
            var userLockLegacyEntry = LatestEntry(oemInfoEntries, 0x5c);
            var rootTypeEntry = LatestEntry(oemInfoEntries, 0x43);
            var rdlLockEntry = LatestEntry(oemInfoEntries, 0x82);

            byte[]? usrKey = TryParseHex(usrKeyRaw);
            if (usrKey == null || usrKey.Length != 32)
            {
                var altKey = TryParseHex(usrKeyAltRaw);
                if (altKey != null && altKey.Length == 32)
                {
                    usrKey = altKey;
                    usrKeyRaw = usrKeyAltRaw;
                }
            }
            bool? hmacUnlocked = null;
            bool? hmacRelocked = null;
            string? hmacUnlockedHex = null;
            string? hmacRelockedHex = null;

            if (usrKey != null && userLockEntry != null)
            {
                if (userLockEntry.Data.Length < 32)
                    notes.Add($"oeminfo 0x5d has {userLockEntry.Data.Length} bytes; expected 32 for the HMAC comparison.");

                byte[] unlocked = HMACSHA256.HashData(usrKey, Encoding.ASCII.GetBytes("ABABCDCDEF"));
                byte[] relocked = HMACSHA256.HashData(usrKey, Encoding.ASCII.GetBytes("EFEFABCDEF"));
                hmacUnlockedHex = Convert.ToHexString(unlocked);
                hmacRelockedHex = Convert.ToHexString(relocked);
                int compareLength = Math.Min(32, userLockEntry.Data.Length);
                hmacUnlocked = compareLength == 32 && unlocked.AsSpan().SequenceEqual(userLockEntry.Data.AsSpan(0, compareLength));
                hmacRelocked = compareLength == 32 && relocked.AsSpan().SequenceEqual(userLockEntry.Data.AsSpan(0, compareLength));
            }
            else if (usrKey == null)
            {
                notes.Add("USRKEY could not be parsed as hex from `getvar nve:USRKEY`; HMAC verification was skipped.");
            }

            string? oemInfoSha = oemInfo != null ? Sha256Hex(oemInfo) : null;
            byte[]? nvme = File.Exists(nvmePath) ? await File.ReadAllBytesAsync(nvmePath) : null;
            string? nvmeSha = nvme != null ? Sha256Hex(nvme) : null;
            byte[]? fastboot = File.Exists(fastbootPath) ? await File.ReadAllBytesAsync(fastbootPath) : null;
            string? fastbootSha = fastboot != null ? Sha256Hex(fastboot) : null;

            byte[]? otaFastboot = null;
            string? otaFastbootSha = null;
            bool? fastbootMatchesOta = null;
            int otaFastbootOffset = -1;
            if (!string.IsNullOrWhiteSpace(baseUpdateAppPath) && File.Exists(baseUpdateAppPath))
            {
                progress?.Report("Extracting FASTBOOT from UPDATE.APP...");
                otaFastboot = await TryExtractUpdateAppPartitionAsync(baseUpdateAppPath, "FASTBOOT", outputDirectory, notes);
                if (otaFastboot != null)
                {
                    otaFastbootSha = Sha256Hex(otaFastboot);
                    if (fastboot != null)
                        fastbootMatchesOta = ContainsSequence(fastboot, otaFastboot, out otaFastbootOffset);
                }
            }

            byte[]? factoryFastboot = null;
            string? factorySha = null;
            bool? fastbootMatchesFactory = null;
            int factoryFastbootOffset = -1;
            if (!string.IsNullOrWhiteSpace(factoryFastbootPath) && File.Exists(factoryFastbootPath))
            {
                factoryFastboot = await File.ReadAllBytesAsync(factoryFastbootPath);
                factorySha = Sha256Hex(factoryFastboot);
                if (fastboot != null)
                    fastbootMatchesFactory = ContainsSequence(fastboot, factoryFastboot, out factoryFastbootOffset);
            }

            string fbState = ParseOemLine(lockState, "FB LockState:");
            string userState = ParseOemLine(lockState, "USER LockState:");

            string report = BuildReport(
                outputDirectory,
                lockState,
                bootInfo,
                usrKeyRaw,
                usrKeyAltRaw,
                fblockRaw,
                usrKey,
                oemInfoEntries,
                userLockEntry,
                userLockLegacyEntry,
                rootTypeEntry,
                rdlLockEntry,
                hmacUnlocked,
                hmacRelocked,
                hmacUnlockedHex,
                hmacRelockedHex,
                oemInfoPath,
                nvmePath,
                fastbootPath,
                oemInfoSha,
                nvmeSha,
                fastbootSha,
                otaFastboot,
                otaFastbootSha,
                factoryFastboot,
                factorySha,
                fastbootMatchesOta,
                fastbootMatchesFactory,
                otaFastbootOffset,
                factoryFastbootOffset,
                oemInfoDump,
                nvmeDump,
                fastbootDump,
                fbState,
                userState,
                notes);

            var summary = new StringBuilder();
            summary.AppendLine($"FB LockState: {fbState}");
            summary.AppendLine($"USER LockState: {userState}");
            string userLockSummary = userLockEntry == null
                ? "no presente"
                : hmacUnlocked == true
                    ? "UNLOCKED"
                    : hmacRelocked == true
                        ? "RELOCKED"
                        : hmacUnlocked == null
                            ? "presente (HMAC no verificado)"
                            : "LOCKED/otro";
            summary.AppendLine($"oeminfo 0x5d (persistente): {userLockSummary}");
            summary.AppendLine($"oeminfo 0x82 (RDLOCK): {(rdlLockEntry != null ? $"presente, {rdlLockEntry.DataLength} bytes" : "ausente")}");
            summary.AppendLine($"fastboot: {(fastbootMatchesOta == true ? "stock OTA" : fastbootMatchesFactory == true ? "loader de fábrica" : fastboot != null ? "imagen desconocida" : "sin dump")}");
            if (notes.Count > 0)
                summary.AppendLine($"Notas: {notes.Count} (ver reporte)");

            return new LockDiagnosticResult { ReportText = report, Summary = summary.ToString().Trim() };
        }

        private static string BuildReport(
            string outputDirectory,
            string lockState,
            string bootInfo,
            string usrKeyRaw,
            string usrKeyAltRaw,
            string fblockRaw,
            byte[]? usrKey,
            List<OemInfoEntry> oemInfoEntries,
            OemInfoEntry? userLockEntry,
            OemInfoEntry? userLockLegacyEntry,
            OemInfoEntry? rootTypeEntry,
            OemInfoEntry? rdlLockEntry,
            bool? hmacUnlocked,
            bool? hmacRelocked,
            string? hmacUnlockedHex,
            string? hmacRelockedHex,
            string oemInfoPath,
            string nvmePath,
            string fastbootPath,
            string? oemInfoSha,
            string? nvmeSha,
            string? fastbootSha,
            byte[]? otaFastboot,
            string? otaFastbootSha,
            byte[]? factoryFastboot,
            string? factorySha,
            bool? fastbootMatchesOta,
            bool? fastbootMatchesFactory,
            int otaFastbootOffset,
            int factoryFastbootOffset,
            ProcessResult? oemInfoDump,
            ProcessResult? nvmeDump,
            ProcessResult? fastbootDump,
            string fbState,
            string userState,
            List<string> notes)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Kirin-Tool - Lock diagnostic (read-only)");
            sb.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Output: {outputDirectory}");
            sb.AppendLine();

            sb.AppendLine("== Running fastboot ==");
            sb.AppendLine("oem lock-state info:");
            sb.AppendLine(lockState.Trim());
            sb.AppendLine("oem get-bootinfo:");
            sb.AppendLine(bootInfo.Trim());
            sb.AppendLine($"Parsed: FB LockState={fbState}, USER LockState={userState}");
            sb.AppendLine();

            sb.AppendLine("== NV items ==");
            sb.AppendLine($"getvar nve:USRKEY: {DisplayOrEmpty(usrKeyRaw)}");
            sb.AppendLine($"getvar nve:USER (fallback): {DisplayOrEmpty(usrKeyAltRaw)}");
            sb.AppendLine($"  parsed bytes: {usrKey?.Length ?? 0}");
            sb.AppendLine($"getvar nve:FBLOCK: {DisplayOrEmpty(fblockRaw)}");
            sb.AppendLine($"  decoded FBLOCK: {DescribeFblock(fblockRaw)}");
            sb.AppendLine();

            sb.AppendLine("== Dumps ==");
            sb.AppendLine($"oeminfo:  {DumpStatus(oemInfoPath, oemInfoSha, oemInfoDump)}");
            sb.AppendLine($"nvme:     {DumpStatus(nvmePath, nvmeSha, nvmeDump)}");
            sb.AppendLine($"fastboot: {DumpStatus(fastbootPath, fastbootSha, fastbootDump)}");
            sb.AppendLine();

            sb.AppendLine("== OEMINFO entries ==");
            if (oemInfoEntries.Count == 0)
            {
                sb.AppendLine("(none parsed)");
            }
            else
            {
                foreach (var e in oemInfoEntries)
                {
                    sb.AppendLine($"offset=0x{e.Offset:X6} version={e.Version} id=0x{e.Id:X} age={e.Age} len=0x{e.DataLength:X} sha256={Sha256Hex(e.Data)}");
                    if (e.Id is 0x5c or 0x5d or 0x82)
                        sb.AppendLine($"  data: {HexRange(e.Data, 0, Math.Min(e.Data.Length, 64))}");
                }
            }
            sb.AppendLine();

            sb.AppendLine("== USERLOCK record (oeminfo 0x5d) ==");
            sb.AppendLine($"present: {userLockEntry != null}");
            if (userLockEntry != null)
            {
                sb.AppendLine($"data (hex): {HexRange(userLockEntry.Data, 0, Math.Min(userLockEntry.Data.Length, 32))}");
                sb.AppendLine($"HMAC(USRKEY, \"ABABCDCDEF\"): {hmacUnlockedHex ?? "n/a"}  match={hmacUnlocked}");
                sb.AppendLine($"HMAC(USRKEY, \"EFEFABCDEF\"): {hmacRelockedHex ?? "n/a"}  match={hmacRelocked}");
            }
            if (userLockLegacyEntry != null)
                sb.AppendLine($"legacy 0x5c present: {HexRange(userLockLegacyEntry.Data, 0, Math.Min(userLockLegacyEntry.Data.Length, 16))}");
            if (rootTypeEntry != null)
                sb.AppendLine($"0x43 present: {HexRange(rootTypeEntry.Data, 0, Math.Min(rootTypeEntry.Data.Length, 16))}");
            sb.AppendLine();

            sb.AppendLine("== RDLOCK record (oeminfo 0x82) ==");
            sb.AppendLine($"present: {rdlLockEntry != null}");
            if (rdlLockEntry != null)
                sb.AppendLine($"len=0x{rdlLockEntry.DataLength:X} sha256={Sha256Hex(rdlLockEntry.Data)} first32={HexRange(rdlLockEntry.Data, 0, Math.Min(rdlLockEntry.Data.Length, 32))}");
            sb.AppendLine();

            sb.AppendLine("== Fastboot image comparison ==");
            sb.AppendLine($"fastboot dump:        {fastbootSha ?? "n/a"}");
            sb.AppendLine($"UPDATE.APP FASTBOOT:  {otaFastbootSha ?? "n/a"}  match={fastbootMatchesOta} offset={(otaFastbootOffset >= 0 ? $"0x{otaFastbootOffset:X}" : "n/a")}");
            sb.AppendLine($"factory fastboot.img: {factorySha ?? "n/a"}  match={fastbootMatchesFactory} offset={(factoryFastbootOffset >= 0 ? $"0x{factoryFastbootOffset:X}" : "n/a")}");
            sb.AppendLine($"header dump    @0x180: {HeaderHex(fastbootSha != null ? fastbootPath : null, 0x180, 0x40)}");
            sb.AppendLine($"header OTA     @0x180: {HeaderHex(otaFastboot, 0x180, 0x40)}");
            sb.AppendLine($"header factory @0x180: {HeaderHex(factoryFastboot, 0x180, 0x40)}");
            sb.AppendLine();

            sb.AppendLine("== Notes ==");
            if (notes.Count == 0)
                sb.AppendLine("(none)");
            else
                foreach (var note in notes)
                    sb.AppendLine($"- {note}");
            sb.AppendLine();

            sb.AppendLine("== Conclusion ==");
            string conclusion;
            bool lockStateReadable = !userState.Equals("Unknown", StringComparison.OrdinalIgnoreCase)
                                  && !fbState.Equals("Unknown", StringComparison.OrdinalIgnoreCase);

            if (!lockStateReadable)
                conclusion = "No se pudo leer `oem lock-state info` desde el fastboot en ejecución; el diagnóstico de persistencia queda incompleto.";
            else if (userState.Contains("UNLOCKED", StringComparison.OrdinalIgnoreCase) && hmacUnlocked == false)
                conclusion = "El fastboot en ejecución reporta USER UNLOCKED, pero el registro persistente 0x5d no coincide con unlocked: el estado mostrado es del loader temporal en RAM, no del almacenamiento.";
            else if (!userState.Contains("UNLOCKED", StringComparison.OrdinalIgnoreCase) && hmacUnlocked == true)
                conclusion = "El registro persistente 0x5d está UNLOCKED, pero el fastboot en ejecución reporta USER LOCKED: el lector no está leyendo 0x5d (EMUI 10+ / RDLOCK o loader stock).";
            else if (hmacUnlocked == true)
                conclusion = "El registro persistente 0x5d está UNLOCKED y el fastboot en ejecución lo refleja.";
            else
                conclusion = "No se pudo probar que el registro persistente 0x5d esté unlocked con los datos disponibles.";

            if (fastbootMatchesOta == true)
                conclusion += " La partición fastboot coincide con el bloque FASTBOOT del UPDATE.APP: el full OTA instaló el loader stock.";
            else if (fastbootMatchesFactory == true)
                conclusion += " La partición fastboot coincide con el loader de fábrica.";

            if (rdlLockEntry != null)
                conclusion += " Hay un registro RDLOCK 0x82 presente (firma no verificada en este diagnóstico).";

            sb.AppendLine(conclusion);
            return sb.ToString();
        }

        private async Task<ProcessResult?> TryDumpPartitionAsync(string partitionName, string outputPath, List<string> notes)
        {
            try
            {
                if (File.Exists(outputPath))
                    File.Delete(outputPath);

                var result = await _fastbootClient.DumpPartitionAsync(partitionName, outputPath);
                bool hasFile = File.Exists(outputPath) && new FileInfo(outputPath).Length > 0;
                if (!hasFile)
                {
                    notes.Add($"dump-emmc {partitionName} failed: {FirstLine(result.Output)}");
                    return result;
                }

                if (!result.IsSuccess)
                    notes.Add($"dump-emmc {partitionName} returned exit code {result.ExitCode} but produced {new FileInfo(outputPath).Length} bytes; using the file.");

                return result;
            }
            catch (Exception ex)
            {
                notes.Add($"dump-emmc {partitionName} threw: {ex.Message}");
                return null;
            }
        }

        private static async Task<string> TryReadStringAsync(Func<Task<string>> action, string label, List<string> notes)
        {
            try
            {
                return await action();
            }
            catch (Exception ex)
            {
                notes.Add($"{label} failed: {ex.Message}");
                return string.Empty;
            }
        }

        private static async Task<byte[]?> TryExtractUpdateAppPartitionAsync(
            string updateAppPath,
            string partitionName,
            string outputDirectory,
            List<string> notes)
        {
            try
            {
                using var updateApp = new UpdateApp(updateAppPath);
                var partition = updateApp.Partitions.FirstOrDefault(
                    p => p.Name.Equals(partitionName, StringComparison.OrdinalIgnoreCase));

                if (partition == null)
                {
                    notes.Add($"UPDATE.APP: no {partitionName} partition found.");
                    return null;
                }

                string tempPath = Path.Combine(outputDirectory, $"{partitionName}.from-update-app.img");
                await updateApp.ExtractPartition(partition, tempPath);

                if (!File.Exists(tempPath))
                {
                    notes.Add($"UPDATE.APP: extraction of {partitionName} produced no file.");
                    return null;
                }

                return await File.ReadAllBytesAsync(tempPath);
            }
            catch (Exception ex)
            {
                notes.Add($"UPDATE.APP comparison failed: {ex.Message}");
                return null;
            }
        }

        private static List<OemInfoEntry> ParseOemInfo(byte[] data)
        {
            var entries = new List<OemInfoEntry>();

            for (int offset = 0; offset + OemInfoDataOffset <= data.Length; offset += OemInfoBlockSize)
            {
                if (offset + 24 > data.Length)
                    break;

                if (data[offset] != OemInfoMagic[0])
                    continue;

                if (!data.AsSpan(offset, OemInfoMagic.Length).SequenceEqual(OemInfoMagic))
                    continue;

                int version = BitConverter.ToInt32(data, offset + 8);
                int id = BitConverter.ToInt32(data, offset + 12);
                int dataLength = BitConverter.ToInt32(data, offset + 20);
                int age = BitConverter.ToInt32(data, offset + 24);
                if (dataLength < 0)
                    continue;

                int dataStart = offset + OemInfoDataOffset;
                int available = Math.Min(dataLength, data.Length - dataStart);
                available = Math.Min(available, OemInfoBlockSize - OemInfoDataOffset);

                var payload = new byte[Math.Max(0, available)];
                if (payload.Length > 0)
                    Array.Copy(data, dataStart, payload, 0, payload.Length);

                entries.Add(new OemInfoEntry
                {
                    Offset = offset,
                    Version = version,
                    Id = id,
                    Age = age,
                    DataLength = dataLength,
                    Data = payload
                });
            }

            return entries;
        }

        private static OemInfoEntry? LatestEntry(List<OemInfoEntry> entries, int id) =>
            entries.Where(e => e.Id == id)
                .OrderByDescending(e => e.Age)
                .ThenByDescending(e => e.Offset)
                .FirstOrDefault();

        private static bool ContainsSequence(byte[] haystack, byte[] needle, out int offset)
        {
            offset = -1;
            if (needle.Length == 0 || haystack.Length < needle.Length)
                return false;

            offset = haystack.AsSpan().IndexOf(needle.AsSpan());
            return offset >= 0;
        }

        private static byte[]? TryParseHex(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            string text = value.Trim();
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                text = text[2..];

            if (text.Length == 0 || (text.Length & 1) != 0)
                return null;

            foreach (char c in text)
                if (!Uri.IsHexDigit(c))
                    return null;

            try
            {
                return Convert.FromHexString(text);
            }
            catch
            {
                return null;
            }
        }

        private static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data));

        private static string HexRange(byte[] data, int offset, int length)
        {
            if (data.Length == 0 || length <= 0)
                return "(empty)";

            int start = Math.Max(0, Math.Min(offset, data.Length));
            int count = Math.Min(length, data.Length - start);
            return count == 0 ? "(empty)" : Convert.ToHexString(data.AsSpan(start, count));
        }

        private static string HeaderHex(string? path, int offset, int length)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return "n/a";

            try
            {
                var data = File.ReadAllBytes(path);
                return HexRange(data, offset, length);
            }
            catch
            {
                return "n/a";
            }
        }

        private static string HeaderHex(byte[]? data, int offset, int length)
        {
            if (data == null)
                return "n/a";

            return HexRange(data, offset, length);
        }

        private static string DisplayOrEmpty(string? value) =>
            string.IsNullOrWhiteSpace(value) ? "(empty)" : value.Trim();

        private static string DescribeFblock(string raw)
        {
            var bytes = TryParseHex(raw);
            if (bytes == null || bytes.Length == 0)
                return "n/a";

            return $"len={bytes.Length} first=0x{bytes[0]:X2}";
        }

        private static string ParseOemLine(string output, string key)
        {
            if (string.IsNullOrEmpty(output))
                return "Unknown";

            var line = output.Split('\n', '\r')
                .Select(l => l.Trim())
                .FirstOrDefault(l => l.Contains(key, StringComparison.OrdinalIgnoreCase));

            if (line == null)
                return "Unknown";

            int keyIndex = line.IndexOf(key, StringComparison.OrdinalIgnoreCase);
            return line[(keyIndex + key.Length)..].Trim();
        }

        private static string DumpStatus(string path, string? sha, ProcessResult? result)
        {
            if (File.Exists(path))
            {
                long length = new FileInfo(path).Length;
                return $"{path} ({length} bytes, sha256={sha})";
            }

            return $"failed ({FirstLine(result?.Output ?? "no output")})";
        }

        private static string FirstLine(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return "no output";

            var line = text.Split('\n', '\r')
                .FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));

            return (line ?? "no output").Trim();
        }
    }
}
