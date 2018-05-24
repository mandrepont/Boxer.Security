namespace Boxer.Security

type ICryptography =
    abstract Encrypt: (byte[] -> byte[])
    abstract Decrypt: (byte[] -> byte[])
