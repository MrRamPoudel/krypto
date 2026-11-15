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
        _key = [.. key];
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        // Validate that it is not disposed
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] output = new byte[CryptoValidation.AddLengths(plaintext.Length, NonceSize + TagSize)];

        // Add nonce
        RandomNumberGenerator.Fill(output.AsSpan(0, NonceSize));
        using var aes = new AesGcm(_key, TagSize);
        try
        {
            aes.Encrypt(
                output.AsSpan(0, NonceSize),
                plaintext,
                output.AsSpan(NonceSize, plaintext.Length),
                output.AsSpan(NonceSize + plaintext.Length),
                associatedData
            );
   
            return output;
        }
        catch (CryptographicException ex)
        {
            throw new GeneralCryptoException("Encryption failed.", ex);
        }
        
    }

    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData)
    {

        ObjectDisposedException.ThrowIf(_disposed, this);
        if (ciphertext.Length < NonceSize + TagSize)
        {
            throw new GeneralCryptoException("Decryption failed.");
        }

        byte[] plaintext = new byte[ciphertext.Length - NonceSize - TagSize];

        using var aes = new AesGcm(_key, TagSize);
        try
        {
            aes.Decrypt(
            ciphertext[..NonceSize],
            ciphertext.Slice(NonceSize, plaintext.Length),
            ciphertext[^TagSize..], plaintext, associatedData
            );

            return plaintext;
        } catch (CryptographicException exception){
            throw new GeneralCryptoException("Decryption failed.", exception);
        }

    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_key);
        _disposed = true;
    }
}