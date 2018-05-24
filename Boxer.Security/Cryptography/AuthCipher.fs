namespace Boxer.Security.Cryptography

type CryptoCounter = {
    Count: uint16
} with
    member this.Key1 = this.Count &&& 255us |> byte
    member this.Key2 = this.Count >>> 8 |> byte
    member this.Increment = { Count = this.Count + 1us }

type AuthCipherContext = {
    DecryptCounter: CryptoCounter
    EncryptCounter: CryptoCounter
    CryptKey1: byte array
    CryptKey2: byte array
} with
    static member InitContext = {
        DecryptCounter = { Count = 0us }
        EncryptCounter = { Count = 0us }
        CryptKey1 =
            Array.zeroCreate 0xFF
            |> Array.scan (fun i_key1 _ -> 
                (0x0Fuy + i_key1 * 0xFAuy) * i_key1 + 0x13uy) 0x9Duy
        CryptKey2 = 
            Array.zeroCreate 0xFF
            |> Array.scan (fun i_key2 _ -> 
                (0x79uy - i_key2 * 0x5Cuy) * i_key2 + 0x6Duy) 0x62uy
    }