using krypto.krypto.Core;

namespace krypto.krypto.Internal;

internal static class CryptoValidation
{
    internal static int AddLengths(int length, int overhead)
    {
        if (length < 0 || overhead < 0 || length > int.MaxValue - overhead)
        {
            throw new GeneralCryptoException("Input is too long");
        }
        return length + overhead;

    }
    internal static void Version(uint version)
    {
        if (version != 0)
        {
            throw new GeneralCryptoException("Only version 0 keys and parameters are supported.");
        }
    }

    internal static void AesKeySize(long keySize)
    {
        if (keySize is not (16 or 32))
        {
            throw new GeneralCryptoException("AES keys must contain 16 or 32 bytes.");
        }
    }
}