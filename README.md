![Ekran görüntüsü 2024-09-07 165456](https://github.com/user-attachments/assets/3dedd3ed-5474-48cb-be26-af885e378dc8)
HashGopher is a basic hashcat clone made in Go.

## Installation

You can use both git clone and go get to clone my repository. 
Now you need to build `main.go` to use it. Here's how you can do it:
```
go build main.go
```
Now, we are ready to use it!

## Usage

Since I am using Windows my `main.go` is built as `main.exe`. HashGopher has two versions; file and single. In file version it takes two arguments, path to hashlist and path to wordlist.
It'll use wordlist to bruteforce each hash in hashlist.
Single version is similiar to file version, it takes two arguments aswell but instead of hashlist it takes a hash and path to wordlist. It'll use the wordlist to bruteforce the hash.

Example file mode usage
```
main.exe file hashlist.txt wordlist.txt

```
Example single mode usage

```
main.exe b6c30f73858d7ee4926eb1f757374e0e wordlist.txt

```

## Supported hash types

+ MD5
+ MD4
+ MD2
+ SHA1
+ SHA256
+ SHA224
+ SHA384
+ SHA512
+ SHA3-256
+ SHA3-512
+ SHA3-224
+ SHA3-384
+ BCRYPT
+ RIPEMD160
+ RIPEMD128
+ RIPEMD256
+ RIPEMD320
+ WHIRLPOOL
+ BLAKE2B-256
+ BLAKE2B-512
+ BLAKE2B-384
+ TIGER
+ TIGER2
+ MURMUR3-32
+ MURMUR3-64
+ MURMUR3-128
+ XXHASH

 # Note

 It doesn't work with go routines since I do not know how to use them. (You can contribute to this project and add it yourself :D)
 It still works fast since it is written in go, I think it checks 30k words in 9-10 minutes but it depends on hardware too.
 Also, don't use it for illegal purposes.

 Happy cracking!!!
