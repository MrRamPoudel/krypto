namespace krypto.krypto.Core;

public class GeneralCryptoException : Exception
{
    public GeneralCryptoException(string message) : base(message) {}

    public GeneralCryptoException(string message, Exception ex) : base(message, ex) {}
} 