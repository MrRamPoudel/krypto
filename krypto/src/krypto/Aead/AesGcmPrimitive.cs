using System.Security.Cryptography;
using krypto.krypto.Core;
using krypto.krypto.Internal;

namespace krypto.krypto.Aead;

internal sealed class AesGcmPrimitive : IAead, IDisposable
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private readonly byte[] _key;
    private bool _disposed;

    internal AesGcmPrimitive(ReadOnlySpan<byte> key)
    {
        CryptoValidation.AesKeySize(key.Length);
        _key = key.ToArray();
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {

        throw new NotImplementedException();
        
    }

    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData)
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        throw new NotImplementedException();
    }
}