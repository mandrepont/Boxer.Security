module Box.SecurityTest.AuthCipherTest

open Xunit
open Boxer.Security.Cryptography
open FsUnit.Xunit

//Keys extracted from other working versions.
let key1 = [|157uy; 144uy; 131uy; 138uy; 209uy; 140uy; 231uy; 246uy; 37uy; 40uy; 235uy; 130uy; 153uy; 100uy; 143uy; 46uy; 45uy; 64uy; 211uy; 250uy; 225uy; 188uy; 183uy; 230uy; 181uy; 216uy; 59uy; 242uy; 169uy; 148uy; 95uy; 30uy; 189uy; 240uy; 35uy; 106uy; 241uy; 236uy; 135uy; 214uy; 69uy; 136uy; 139uy; 98uy; 185uy; 196uy; 47uy; 14uy; 77uy; 160uy; 115uy; 218uy; 1uy; 28uy; 87uy; 198uy; 213uy; 56uy; 219uy; 210uy; 201uy; 244uy; 255uy; 254uy; 221uy; 80uy; 195uy; 74uy; 17uy; 76uy; 39uy; 182uy; 101uy; 232uy; 43uy; 66uy; 217uy; 36uy; 207uy; 238uy; 109uy; 0uy; 19uy; 186uy; 33uy; 124uy; 247uy; 166uy; 245uy; 152uy; 123uy; 178uy; 233uy; 84uy; 159uy; 222uy; 253uy; 176uy; 99uy; 42uy; 49uy; 172uy; 199uy; 150uy; 133uy; 72uy; 203uy; 34uy; 249uy; 132uy; 111uy; 206uy; 141uy; 96uy; 179uy; 154uy; 65uy; 220uy; 151uy; 134uy; 21uy; 248uy; 27uy; 146uy; 9uy; 180uy; 63uy; 190uy; 29uy; 16uy; 3uy; 10uy; 81uy; 12uy; 103uy; 118uy; 165uy; 168uy; 107uy; 2uy; 25uy; 228uy; 15uy; 174uy; 173uy; 192uy; 83uy; 122uy; 97uy; 60uy; 55uy; 102uy; 53uy; 88uy; 187uy; 114uy; 41uy; 20uy; 223uy; 158uy; 61uy; 112uy; 163uy; 234uy; 113uy; 108uy; 7uy; 86uy; 197uy; 8uy; 11uy; 226uy; 57uy; 68uy; 175uy; 142uy; 205uy; 32uy; 243uy; 90uy; 129uy; 156uy; 215uy; 70uy; 85uy; 184uy; 91uy; 82uy; 73uy; 116uy; 127uy; 126uy; 93uy; 208uy; 67uy; 202uy; 145uy; 204uy; 167uy; 54uy; 229uy; 104uy; 171uy; 194uy; 89uy; 164uy; 79uy; 110uy; 237uy; 128uy; 147uy; 58uy; 161uy; 252uy; 119uy; 38uy; 117uy; 24uy; 251uy; 50uy; 105uy; 212uy; 31uy; 94uy; 125uy; 48uy; 227uy; 170uy; 177uy; 44uy; 71uy; 22uy; 5uy; 200uy; 75uy; 162uy; 121uy; 4uy; 239uy; 78uy; 13uy; 224uy; 51uy; 26uy; 193uy; 92uy; 23uy; 6uy; 149uy; 120uy; 155uy; 18uy; 137uy; 52uy; 191uy; 62uy; |]
let key2 = [|98uy; 79uy; 232uy; 21uy; 222uy; 235uy; 4uy; 145uy; 26uy; 199uy; 224uy; 77uy; 22uy; 227uy; 124uy; 73uy; 210uy; 63uy; 216uy; 133uy; 78uy; 219uy; 244uy; 1uy; 138uy; 183uy; 208uy; 189uy; 134uy; 211uy; 108uy; 185uy; 66uy; 47uy; 200uy; 245uy; 190uy; 203uy; 228uy; 113uy; 250uy; 167uy; 192uy; 45uy; 246uy; 195uy; 92uy; 41uy; 178uy; 31uy; 184uy; 101uy; 46uy; 187uy; 212uy; 225uy; 106uy; 151uy; 176uy; 157uy; 102uy; 179uy; 76uy; 153uy; 34uy; 15uy; 168uy; 213uy; 158uy; 171uy; 196uy; 81uy; 218uy; 135uy; 160uy; 13uy; 214uy; 163uy; 60uy; 9uy; 146uy; 255uy; 152uy; 69uy; 14uy; 155uy; 180uy; 193uy; 74uy; 119uy; 144uy; 125uy; 70uy; 147uy; 44uy; 121uy; 2uy; 239uy; 136uy; 181uy; 126uy; 139uy; 164uy; 49uy; 186uy; 103uy; 128uy; 237uy; 182uy; 131uy; 28uy; 233uy; 114uy; 223uy; 120uy; 37uy; 238uy; 123uy; 148uy; 161uy; 42uy; 87uy; 112uy; 93uy; 38uy; 115uy; 12uy; 89uy; 226uy; 207uy; 104uy; 149uy; 94uy; 107uy; 132uy; 17uy; 154uy; 71uy; 96uy; 205uy; 150uy; 99uy; 252uy; 201uy; 82uy; 191uy; 88uy; 5uy; 206uy; 91uy; 116uy; 129uy; 10uy; 55uy; 80uy; 61uy; 6uy; 83uy; 236uy; 57uy; 194uy; 175uy; 72uy; 117uy; 62uy; 75uy; 100uy; 241uy; 122uy; 39uy; 64uy; 173uy; 118uy; 67uy; 220uy; 169uy; 50uy; 159uy; 56uy; 229uy; 174uy; 59uy; 84uy; 97uy; 234uy; 23uy; 48uy; 29uy; 230uy; 51uy; 204uy; 25uy; 162uy; 143uy; 40uy; 85uy; 30uy; 43uy; 68uy; 209uy; 90uy; 7uy; 32uy; 141uy; 86uy; 35uy; 188uy; 137uy; 18uy; 127uy; 24uy; 197uy; 142uy; 27uy; 52uy; 65uy; 202uy; 247uy; 16uy; 253uy; 198uy; 19uy; 172uy; 249uy; 130uy; 111uy; 8uy; 53uy; 254uy; 11uy; 36uy; 177uy; 58uy; 231uy; 0uy; 109uy; 54uy; 3uy; 156uy; 105uy; 242uy; 95uy; 248uy; 165uy; 110uy; 251uy; 20uy; 33uy; 170uy; 215uy; 240uy; 221uy; 166uy; 243uy; 140uy; 217uy; |]
let baseBuffer = [|116uy; 101uy; 115uy; 116uy; 105uy; 110uy; 103uy; |]
let encipherBuffer = [|2uy; 30uy; 108uy; 21uy; 159uy; 178uy; 73uy; |]
let decipherBuffer = [|101uy; 169uy; 157uy; 3uy; 240uy; 127uy; 171uy; |]
let context = AuthCipherContext.InitContext
let authCipher = AuthCipher(context)

[<Fact>]
let ``ensure key1 matches`` () =
    context.CryptKey1 |> should equal key1

[<Fact>]
let ``ensure key2 matches`` () =
    context.CryptKey2 |> should equal key2

[<Theory>]
[<InlineData(0, 0)>]
[<InlineData(255, 255)>]
[<InlineData(256, 0)>]
[<InlineData(36423, 71)>]
[<InlineData(182, 182)>]
let ``Crypto Counter Key1 Valid`` count expectedKey1 = 
    let cryptoCounter = { Count = count }
    cryptoCounter.Key1 |> should equal expectedKey1
    
[<Theory>]
[<InlineData(0, 0)>]
[<InlineData(255, 0)>]
[<InlineData(256, 1)>]
[<InlineData(36423, 142)>]
[<InlineData(550, 2)>]
let ``Crypto Counter Key2 Valid`` count expectedKey2 = 
    let cryptoCounter = { Count = count }
    cryptoCounter.Key2 |> should equal expectedKey2

[<Fact>]
let ``Encipher test`` () =
    AuthCipher.encipher context baseBuffer |> should equal encipherBuffer

[<Fact>]
let ``Decipher test`` () = 
    AuthCipher.decipher { context with DecryptCounter = { Count = encipherBuffer.Length } } encipherBuffer
    |> should equal baseBuffer