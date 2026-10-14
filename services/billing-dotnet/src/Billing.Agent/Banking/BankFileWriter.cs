using System.Globalization;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Payouts;

namespace Tallowbrook.Billing.Agent.Banking;

/// <summary>
/// Writes the bank's payment file: a header, the payment records split into fixed-size blocks, and a
/// trailer. Each block is encrypted on its own and carries the checksum of its plain text, so the bank
/// can reject a single damaged block instead of the whole file.
/// </summary>
internal sealed class BankFileWriter(IOptions<BankFileOptions> options, ILogger<BankFileWriter> logger)
{
    private readonly byte[] _bankKey = Convert.FromHexString(options.Value.EncryptionKeyHex);

    public byte[] Write(string batchId, DateOnly executionDate, IReadOnlyList<PayoutInstruction> payments)
    {
        byte[] content = Encoding.Latin1.GetBytes(Render(batchId, executionDate, payments));

        using var output = new MemoryStream();
        using (var writer = new BinaryWriter(output, Encoding.ASCII, leaveOpen: true))
        {
            writer.Write(Encoding.ASCII.GetBytes(BankProfile.FileFormatVersion.PadRight(16)));
            writer.Write(Encoding.ASCII.GetBytes(batchId.PadRight(20)));

            using IncrementalHash control = IncrementalHash.CreateHash(BankProfile.ControlHash);
            int blocks = 0;
            foreach (byte[] block in content.Chunk(BankProfile.BlockSize))
            {
                control.AppendData(block);
                BlockRecord record = EncryptBlock(block);
                writer.Write(record.Iv);
                writer.Write(record.Checksum);
                writer.Write(record.Body.Length);
                writer.Write(record.Body);
                blocks++;
            }

            writer.Write(Encoding.ASCII.GetBytes("TRL"));
            writer.Write(blocks);
            writer.Write(Encoding.ASCII.GetBytes(Convert.ToHexString(control.GetHashAndReset())));
        }

        logger.LogInformation("Payment file {BatchId}: {Count} payment(s), {Bytes} bytes", batchId, payments.Count, output.Length);
        return output.ToArray();
    }

    private BlockRecord EncryptBlock(byte[] block)
    {
        uint blockCrc = Crc32.HashToUInt32(block);
        using TripleDES cipher = TripleDES.Create();
        cipher.Key = _bankKey;
        byte[] iv = RandomNumberGenerator.GetBytes(cipher.BlockSize / 8);
        byte[] encrypted = cipher.EncryptCbc(block, iv, PaddingMode.PKCS7);
        return new BlockRecord(iv, blockCrc, encrypted);
    }

    private string Render(string batchId, DateOnly executionDate, IReadOnlyList<PayoutInstruction> payments)
    {
        var text = new StringBuilder();
        BankFileOptions settings = options.Value;
        text.Append(CultureInfo.InvariantCulture, $"H;{batchId};{settings.OriginatorId};{settings.OriginatorIban};{executionDate:yyyyMMdd};{payments.Count}\n");
        foreach (PayoutInstruction payment in payments)
        {
            text.Append(CultureInfo.InvariantCulture,
                $"P;{payment.Id:N};{Clean(payment.BeneficiaryName, 70)};{payment.BeneficiaryIban};{payment.BeneficiaryBic};{payment.Amount:0.00};{payment.Currency};{Clean(payment.RemittanceText, 140)}\n");
        }

        text.Append(CultureInfo.InvariantCulture, $"S;{payments.Sum(p => p.Amount):0.00}\n");
        return text.ToString();
    }

    // The bank's character set is Latin-1 without the field separator.
    private static string Clean(string value, int max)
    {
        string cleaned = new(value.Where(c => c != ';' && c != '\n' && c <= '\u00ff').ToArray());
        return cleaned.Length <= max ? cleaned : cleaned[..max];
    }

    private readonly record struct BlockRecord(byte[] Iv, uint Checksum, byte[] Body);
}
