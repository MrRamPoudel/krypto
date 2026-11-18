using System.Security.Cryptography;
using krypto.krypto.Core;
using krypto.krypto.Internal;

// AES/CTR/NoPadding: IV || zero padding is the initial 128-bit counter.
// Only this mode transformation is implemented here; AES itself comes from .NET.
namespace krypto.krypto.Aead;
internal sealed class AesCtrTransform : IDisposable
{
    private readonly byte[] _key;
    private bool _disposed;

    internal AesCtrTransform(ReadOnlySpan<byte> key)
    {
        CryptoValidation.AesKeySize(key.Length);
        _key = key.ToArray();
    }

    internal void Transform(ReadOnlySpan<byte> input, ReadOnlySpan<byte> iv, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (iv.Length is < 12 or > 16 || output.Length != input.Length)
        {
            throw new GeneralCryptoException("Invalid AES-CTR input.");
        }

        using var aes = Aes.Create();
        aes.Key = _key;
        Span<byte> counter = stackalloc byte[16];
        Span<byte> block = stackalloc byte[16];
        counter.Clear();
        iv.CopyTo(counter);
        try
        {
            int offset = 0;
            while (offset < input.Length)
            {
                aes.EncryptEcb(counter, block, PaddingMode.None);
                int count = Math.Min(16, input.Length - offset);
                for (int i = 0; i < count; i++)
                {
                    output[offset + i] = (byte)(input[offset + i] ^ block[i]);
                }

                offset += count;
                IncrementCounter(counter);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counter);
            CryptographicOperations.ZeroMemory(block);
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_key);
        _disposed = true;
    }

    private static void IncrementCounter(Span<byte> counter)
    {
        // JCE increments modulo 2^128. A .NET span cannot contain enough blocks
        // to repeat a counter within a call, even if the initial counter wraps.
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            counter[i] = unchecked((byte)(counter[i] + 1));
            if (counter[i] != 0)
            {
                break;
            }
        }
    }
}