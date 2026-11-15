/*
 * Kirin-Tool — persist and verify the signed factory fastboot.
 * See the project LICENSE for the terms that apply to this file.
 */

using Kirin_Tool.Models;
using Kirin_Tool.Utils;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Kirin_Tool.Services
{
    public sealed class FactoryFastbootFlashResult
    {
        public bool ImageValidated { get; set; }
        public bool FlashSucceeded { get; set; }
        public string FlashOutput { get; set; } = "";
        public bool DeviceReappeared { get; set; }
        public string LockStateOutput { get; set; } = "";
        public string BuildNumberOutput { get; set; } = "";
        public bool IsUnlocked { get; set; }
        public string Message { get; set; } = "";
    }

    /// <summary>
    /// Writes a signed factory fastboot image to the fastboot partition and verifies
    /// the persistent lock state after the reboot.
    ///
    /// This is the persistent step: the in-RAM factory loader is temporary, while the
    /// fastboot partition is what the stock boot chain loads on the next boot.
    /// </summary>
    public sealed class FactoryFastbootFlasherService
    {
        private const long MinImageSize = 1024 * 1024;
        private const long MaxImageSize = 32 * 1024 * 1024;

        private readonly FastbootClient _fastbootClient;

        public FactoryFastbootFlasherService(FastbootClient fastbootClient)
        {
            _fastbootClient = fastbootClient;
        }

        public async Task<FactoryFastbootFlashResult> FlashAndVerifyAsync(
            string imagePath,
            string? baseUpdateAppPath,
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var result = new FactoryFastbootFlashResult();

            if (string.IsNullOrWhiteSpace(imagePath) || !File.Exists(imagePath))
            {
                result.Message = "Factory fastboot image not found.";
                return result;
            }

            var info = new FileInfo(imagePath);
            if (info.Length < MinImageSize || info.Length > MaxImageSize)
            {
                result.Message = $"Unexpected image size: {info.Length} bytes. Select a signed factory fastboot.img, not the full UPDATE.APP.";
                return result;
            }

            byte[] imageBytes = await File.ReadAllBytesAsync(imagePath, cancellationToken);

            if (imageBytes.Length >= 0x50
                && imageBytes.AsSpan(0x40, 16).SequenceEqual(Encoding.ASCII.GetBytes("BOOTMAGICNUMBER!")))
            {
                result.Message = "The selected image is the decrypted RAM loader, not the signed on-disk fastboot image. Select the signed factory fastboot.img (container).";
                return result;
            }

            byte[] flashBytes = IsFastbootContainer(imageBytes)
                ? imageBytes.AsSpan(0x1000).ToArray()
                : imageBytes;
            string imageSha = Sha256Hex(flashBytes);

            if (!string.IsNullOrWhiteSpace(baseUpdateAppPath) && File.Exists(baseUpdateAppPath))
            {
                progress?.Report("Checking selected image against UPDATE.APP...");
                byte[]? stockFastboot = await TryExtractFastbootAsync(baseUpdateAppPath, cancellationToken);
                if (stockFastboot != null)
                {
                    string stockSha = Sha256Hex(stockFastboot);
                    bool isStock = imageSha.Equals(stockSha, StringComparison.OrdinalIgnoreCase);
                    if (!isStock && stockFastboot.Length > 0x1000)
                    {
                        // The UPDATE.APP block carries a 0x1000 wrapper; the partition stores the payload.
                        var payload = stockFastboot.AsSpan(0x1000).ToArray();
                        isStock = imageSha.Equals(Sha256Hex(payload), StringComparison.OrdinalIgnoreCase);
                    }

                    if (isStock)
                    {
                        result.Message = "The selected image is the stock FASTBOOT block from UPDATE.APP, not the signed factory fastboot. Select the factory fastboot.img (for example loaders/hisi970/fastboot.img).";
                        return result;
                    }
                }
            }

            result.ImageValidated = true;

            progress?.Report("Flashing fastboot partition...");
            string tempFlashPath = Path.Combine(Path.GetTempPath(), $"kirintool_factory_fastboot_{Guid.NewGuid():N}.img");
            await File.WriteAllBytesAsync(tempFlashPath, flashBytes, cancellationToken);
            ProcessResult? flash = null;
            try
            {
                flash = await _fastbootClient.FlashPartition("fastboot", tempFlashPath);
            }
            finally
            {
                try { File.Delete(tempFlashPath); } catch { }
            }

            result.FlashOutput = flash?.Output ?? "";
            bool flashFailed = result.FlashOutput.Contains("FAILED", StringComparison.OrdinalIgnoreCase)
                            || result.FlashOutput.Contains("error", StringComparison.OrdinalIgnoreCase);
            result.FlashSucceeded = flash != null && !flashFailed
                                 && (flash.IsSuccess || result.FlashOutput.Contains("OKAY", StringComparison.OrdinalIgnoreCase));

            if (!result.FlashSucceeded)
            {
                result.Message = $"Flash command failed: {FirstLine(result.FlashOutput)}";
                return result;
            }

            progress?.Report("Rebooting to bootloader...");
            await _fastbootClient.RebootBootloaderAsync();

            progress?.Report("Waiting for the device to reappear in fastboot...");
            for (int i = 0; i < 90; i++)
            {
                await Task.Delay(1000, cancellationToken);
                if (await _fastbootClient.IsDeviceConnected())
                {
                    result.DeviceReappeared = true;
                    break;
                }
            }

            if (!result.DeviceReappeared)
            {
                result.Message = "The device did not reappear in fastboot after the reboot. The bootloader likely rejected the image. Recover via testpoint, or boot fastboot manually and run the lock diagnostic.";
                return result;
            }

            progress?.Report("Verifying lock state...");
            result.LockStateOutput = await _fastbootClient.OemCommandAsync("lock-state info", timeoutMinutes: 2);
            result.BuildNumberOutput = await _fastbootClient.OemCommandAsync("get-build-number", timeoutMinutes: 2);

            string fbState = ParseOemLine(result.LockStateOutput, "FB LockState:");
            string userState = ParseOemLine(result.LockStateOutput, "USER LockState:");
            result.IsUnlocked = fbState.Contains("UNLOCKED", StringComparison.OrdinalIgnoreCase)
                             && userState.Contains("UNLOCKED", StringComparison.OrdinalIgnoreCase);

            result.Message = result.IsUnlocked
                ? $"Factory fastboot persisted. FB={fbState}, USER={userState}. Build: {FirstLine(result.BuildNumberOutput)}"
                : $"The device booted but reports FB={fbState}, USER={userState}. The xloader likely rejected the factory image (ARB/signature) or the stock loader was restored.";

            return result;
        }

        private static async Task<byte[]?> TryExtractFastbootAsync(string updateAppPath, CancellationToken cancellationToken)
        {
            try
            {
                using var updateApp = new UpdateApp(updateAppPath);
                var partition = updateApp.Partitions.FirstOrDefault(
                    p => p.Name.Equals("FASTBOOT", StringComparison.OrdinalIgnoreCase));

                if (partition == null)
                    return null;

                string tempPath = Path.Combine(Path.GetTempPath(), $"kirintool_stock_fastboot_{Guid.NewGuid():N}.img");
                await updateApp.ExtractPartition(partition, tempPath);

                if (!File.Exists(tempPath))
                    return null;

                byte[] bytes = await File.ReadAllBytesAsync(tempPath, cancellationToken);
                try { File.Delete(tempPath); } catch { }
                return bytes;
            }
            catch
            {
                return null;
            }
        }

        private static bool IsFastbootContainer(byte[] data)
        {
            if (data.Length < 0x1000)
                return false;

            // The UPDATE.APP/board container carries the image name at 0x1C.
            return data.AsSpan(0x1C, 8).SequenceEqual(Encoding.ASCII.GetBytes("fastboot"));
        }

        private static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data));

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
