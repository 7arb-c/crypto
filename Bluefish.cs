using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class BlowfishCipher
{
    private const int P_ARRAY_SIZE = 18;
    private const int S_BOX_COUNT = 4;
    private const int S_BOX_SIZE = 256;
    private const int BLOCK_SIZE = 8; // Blowfish uses 64-bit (8-byte) blocks

    private static readonly uint[] P_INIT = new uint[P_ARRAY_SIZE]
    {
        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0,
        0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
        0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B
    };

    // Initial values for S-boxes (truncated for brevity)
    private static readonly uint[,] S_INIT = new uint[S_BOX_COUNT, S_BOX_SIZE]
    {
        { /* values */ },
        { /* values */ },
        { /* values */ },
        { /* values */ }
    };

    private uint[] P = new uint[P_ARRAY_SIZE];
    private uint[,] S = new uint[S_BOX_COUNT, S_BOX_SIZE];

    public BlowfishCipher(string userKey)
    {
        SetKey(userKey);
    }

    private void SetKey(string userKey)
    {
        if (string.IsNullOrEmpty(userKey))
            throw new ArgumentException("User key cannot be empty.");

        byte[] keyHash;
        using (SHA256 sha256 = SHA256.Create())
        {
            keyHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(userKey));
        }

        Array.Copy(P_INIT, P, P_ARRAY_SIZE);
        Array.Copy(S_INIT, S, S_BOX_COUNT * S_BOX_SIZE);

        int j = 0;
        for (int i = 0; i < P_ARRAY_SIZE; i++)
        {
            P[i] ^= BitConverter.ToUInt32(keyHash, j);
            j = (j + 4) % keyHash.Length;
        }

        uint[] data = new uint[2];
        for (int i = 0; i < P_ARRAY_SIZE; i += 2)
        {
            EncryptBlock(data);
            P[i] = data[0];
            P[i + 1] = data[1];
        }

        for (int i = 0; i < S_BOX_COUNT; i++)
        {
            for (int k = 0; k < S_BOX_SIZE; k += 2)
            {
                EncryptBlock(data);
                S[i, k] = data[0];
                S[i, k + 1] = data[1];
            }
        }
    }

    private uint F(uint x)
    {
        uint a = (x >> 24) & 0xFF;
        uint b = (x >> 16) & 0xFF;
        uint c = (x >> 8) & 0xFF;
        uint d = x & 0xFF;
        return ((S[0, a] + S[1, b]) ^ S[2, c]) + S[3, d];
    }

    private void EncryptBlock(uint[] data)
    {
        uint left = data[0];
        uint right = data[1];

        for (int i = 0; i < 16; ++i)
        {
            left ^= P[i];
            right ^= F(left);
            uint temp = left;
            left = right;
            right = temp;
        }

        uint temp2 = left;
        left = right;
        right = temp2;

        right ^= P[16];
        left ^= P[17];

        data[0] = left;
        data[1] = right;
    }

    private void DecryptBlock(uint[] data)
    {
        uint left = data[0];
        uint right = data[1];

        for (int i = 17; i > 1; --i)
        {
            left ^= P[i];
            right ^= F(left);
            uint temp = left;
            left = right;
            right = temp;
        }

        uint temp2 = left;
        left = right;
        right = temp2;

        right ^= P[1];
        left ^= P[0];

        data[0] = left;
        data[1] = right;
    }

    public void EncryptFile(string inputFilename, string outputFilename)
    {
        byte[] data = File.ReadAllBytes(inputFilename);

        int paddedLen = ((data.Length + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
        Array.Resize(ref data, paddedLen);

        for (int i = 0; i < paddedLen; i += BLOCK_SIZE)
        {
            uint[] block = new uint[2];
            Buffer.BlockCopy(data, i, block, 0, BLOCK_SIZE);
            EncryptBlock(block);
            Buffer.BlockCopy(block, 0, data, i, BLOCK_SIZE);
        }

        File.WriteAllBytes(outputFilename, data);
    }

    public void DecryptFile(string inputFilename, string outputFilename)
    {
        byte[] data = File.ReadAllBytes(inputFilename);

        for (int i = 0; i < data.Length; i += BLOCK_SIZE)
        {
            uint[] block = new uint[2];
            Buffer.BlockCopy(data, i, block, 0, BLOCK_SIZE);
            DecryptBlock(block);
            Buffer.BlockCopy(block, 0, data, i, BLOCK_SIZE);
        }

        File.WriteAllBytes(outputFilename, data);
    }
}

class Program
{
    static void Main()
    {
        try
        {
            BlowfishCipher cipher = new BlowfishCipher("securekey");

            // Encrypt file
            cipher.EncryptFile("plaintext.txt", "ciphertext.bin");

            // Decrypt file
            cipher.DecryptFile("ciphertext.bin", "decrypted.txt");

            Console.WriteLine("Encryption and decryption completed successfully.");
        }
        catch (Exception e)
        {
            Console.WriteLine("Error: " + e.Message);
        }
    }
}
