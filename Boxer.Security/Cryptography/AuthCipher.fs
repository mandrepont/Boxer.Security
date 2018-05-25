namespace Boxer.Security.Cryptography

open Boxer.Security

type CryptoCounter = {
    Count: int
} with
    member this.Key1 = this.Count &&& 255
    member this.Key2 = this.Count >>> 8
    member this.Increment = { Count = this.Count + 1 }

type AuthCipherContext = {
    DecryptCounter: CryptoCounter
    EncryptCounter: CryptoCounter
    CryptKey1: byte array
    CryptKey2: byte array
} with
    static member InitContext = {
        DecryptCounter = { Count = 0 }
        EncryptCounter = { Count = 0 }
        CryptKey1 =
            Array.zeroCreate 0xFF
            |> Array.scan (fun i_key1 _ -> 
                (0x0Fuy + i_key1 * 0xFAuy) * i_key1 + 0x13uy) 0x9Duy
        CryptKey2 = 
            Array.zeroCreate 0xFF
            |> Array.scan (fun i_key2 _ -> 
                (0x79uy - i_key2 * 0x5Cuy) * i_key2 + 0x6Duy) 0x62uy
    }

module AuthCipher = 
    let byteMutation (cryptoCounter: CryptoCounter) (cryptoKey1: byte array) (cryptoKey2: byte array) by =
        let a = by ^^^ 0xABuy
        let b = (a >>> 4) ||| (a <<< 4) |> byte
        let c = b ^^^ cryptoKey1.[cryptoCounter.Key1] ^^^ cryptoKey2.[cryptoCounter.Key2]
        c

    let encipher (context: AuthCipherContext) (buffer: byte array)  = 
        let mutable context = context
        buffer |> Array.map (fun b ->
            let b = byteMutation context.EncryptCounter context.CryptKey1 context.CryptKey2 b
            context <- { context with EncryptCounter = context.EncryptCounter.Increment }
            b)

    let decipher (context: AuthCipherContext) (buffer: byte array)  = 
        let mutable context = context
        buffer |> Array.map (fun b ->
            let b = byteMutation context.DecryptCounter context.CryptKey1 context.CryptKey2 b
            context <- { context with DecryptCounter = context.DecryptCounter.Increment }
            b)

type AuthCipher (context: AuthCipherContext) =
    interface ICryptography with
        member this.Encrypt = 
            let buffer = AuthCipher.encipher context
            let context = { context with EncryptCounter = context.EncryptCounter.Increment }
            buffer
        member this.Decrypt = 
            let buffer = AuthCipher.encipher context
            let context = { context with DecryptCounter = context.DecryptCounter.Increment }
            buffer
            