namespace krypto.krypto.Core;

/// <summary>
/// Interface for Authenticated Encryption with Associated Data (AEAD)

/// Implementations of this interface are secure against adaptive chosen cipher text attacks.
/// Encryption with associated data ensures authenticity (who the sender is) and integrity (the data has not been tampered with) of that data,
/// but not its secrecy. See <see href="https://tools.ietf.org/html/rfc5116" /> for more info
/// </summary>
public interface IAead
{
    /// <summary>
    /// Encrypts plaintext with associatedData as associated authenticated data.
    /// The result ciphertext allows for checking authenticity and integritiy of associated data, but does not guarantee its secrecy
    /// 
    /// </summary>
    /// <param name="plaintext"> the plaintext to be encrypted. It must not be nullable, but can also be an empty (zero-length) byte span</param>
    /// <param name="associatedData">associated data to be authenticated, but not encrypted. Associated data is optional so this parameter is nullable.
    ///                             In this case, the null value is equivalent to an empty span.
    ///                             For successful decryption the same associatedData must be provided alsong with the ciphertext.
    /// </param>
    /// <returns> resulting ciphertext</returns>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData);

    /// <summary>
    /// Decrypts ciphertext with associatedData as associated authenticated data.
    /// The decryption verifies the authenticity and integrity of the associated data, but does not guarantee its secrecy.
    /// 
    /// </summary>
    /// <param name="ciphertext"> the ciphertext to be decrypted. It must not be nullable.</param>
    /// <param name="associatedData">associated data to be authenticated. For successful decryption it must be
    ///                              the same as associatedData used during encryption. Can be null, which is equivalent to an
    ///                              empty (zero-length) byte span.
    /// </param>
    /// <returns> resulting plaintext</returns>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData);


}