package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/c0mm4nd/go-ripemd"
	xxhash2 "github.com/cespare/xxhash"
	"github.com/cxmcc/tiger"
	"github.com/htruong/go-md2"
	"github.com/jzelinskie/whirlpool"
	"github.com/twmb/murmur3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
	"os"
)

func md5Returner(text string) string {
	var hash = md5.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func sha1Returner(text string) string {
	var hash = sha1.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func bcryptChecker(text string, password string) bool {
	var checker = bcrypt.CompareHashAndPassword([]byte(text), []byte(password))
	return checker == nil
}
func sha256Returner(text string) string {
	var hash = sha256.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func sha224Returner(text string) string {
	var hash = sha256.New224()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func md2Returner(text string) string {
	var hash = md2.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func sha512Returner(text string) string {
	var hash = sha512.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func sha3256Returner(text string) string {
	var hash = sha3.New256()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func sha3512Returner(text string) string {
	var hash = sha3.New512()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func sha3224Returner(text string) string {
	var hash = sha3.New224()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func sha3384Returner(text string) string {
	var hash = sha3.New384()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func md4Returner(text string) string {
	var hash = md4.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func sha384Returner(text string) string {
	var hash = sha512.New384()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func ripemd160Returner(text string) string {
	var hash = ripemd.New160()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func ripemd128Returner(text string) string {
	var hash = ripemd.New128()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func ripemd256Returner(text string) string {
	var hash = ripemd.New256()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func ripemd320Returner(text string) string {
	var hash = ripemd.New320()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func whirlpoolReturner(text string) string {
	var hash = whirlpool.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func blake2b256Returner(text string) string {
	var hash, err = blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func blake2b512Returner(text string) string {
	var hash, err = blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func blake2b384Returner(text string) string {
	var hash, err = blake2b.New384(nil)
	if err != nil {
		panic(err)
	}
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func tigerReturner(text string) string {
	var hash = tiger.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func tiger2Returner(text string) string {
	var hash = tiger.New2()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func murmur332(text string) string {
	var hash = murmur3.New32()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func murmur364(text string) string {
	var hash = murmur3.New64()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func murmur3128(text string) string {
	var hash = murmur3.New128()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func xxhashReturner(text string) string {
	var hash = xxhash2.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func Bruteforcer(text string, path string) int {
	var file, err = os.Open(path)
	if err != nil {
		fmt.Printf("%s", err)
		return 1
	}
	defer file.Close()
	var s = bufio.NewScanner(file)

	for s.Scan() {
		fmt.Printf("\033[H\033[2J")
		fmt.Printf("Trying %s\n", s.Text())
		var fiveonetwo = sha512Returner(s.Text())
		if fiveonetwo == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var mdfive = md5Returner(s.Text())
		if mdfive == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var mdfour = md4Returner(s.Text())
		if mdfour == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var shaone = sha1Returner(s.Text())
		if shaone == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var twofivesix = sha256Returner(s.Text())
		if twofivesix == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var Bcrypt = bcryptChecker(text, s.Text())
		if Bcrypt {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var threetwofivesix = sha3256Returner(s.Text())
		if threetwofivesix == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var twotwofour = sha224Returner(s.Text())
		if twotwofour == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var mdtwo = md2Returner(s.Text())
		if mdtwo == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var threeightfour = sha384Returner(s.Text())
		if threeightfour == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var threethreeeightfour = sha3384Returner(s.Text())
		if threethreeeightfour == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var threefiveonetwo = sha3512Returner(s.Text())
		if threefiveonetwo == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var threetwotwofour = sha3224Returner(s.Text())
		if threetwotwofour == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var ripemdonesixzero = ripemd160Returner(s.Text())
		if ripemdonesixzero == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var ripemdonetwoeight = ripemd128Returner(s.Text())
		if ripemdonetwoeight == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var ripemdtwofivesix = ripemd256Returner(s.Text())
		if ripemdtwofivesix == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var ripemdthreetwozero = ripemd320Returner(s.Text())
		if ripemdthreetwozero == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var blake2bthreightfour = blake2b384Returner(s.Text())
		if blake2bthreightfour == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var whirlPool = whirlpoolReturner(s.Text())
		if whirlPool == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var blake2bfiveonesix = blake2b512Returner(s.Text())
		if blake2bfiveonesix == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var blake2btwofivesix = blake2b256Returner(s.Text())
		if blake2btwofivesix == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var tiger2 = tiger2Returner(s.Text())
		if tiger2 == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var tiger1 = tigerReturner(s.Text())
		if tiger1 == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var murmursixytfour = murmur364(s.Text())
		if murmursixytfour == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var murmurthirtytwo = murmur332(s.Text())
		if murmurthirtytwo == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var murmuronetwoeight = murmur3128(s.Text())
		if murmuronetwoeight == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
		var xxh = xxhashReturner(s.Text())
		if xxh == text {
			fmt.Printf("Found the password: %s", s.Text())
			return 0
		}
	}
	fmt.Println("We couldn't find anything.")
	return 1
}

func FileBruteForcer(path string, wordlist string) {
	var f, err = os.Open(wordlist)
	if err != nil {
		fmt.Printf("%v", err)
		return
	}
	defer f.Close()
	var h, err1 = os.Open(path)
	if err1 != nil {
		fmt.Println(err1)
		return
	}
	defer h.Close()

	var hash = bufio.NewScanner(h)
	for hash.Scan() {
		f.Seek(0, 0)
		var word = bufio.NewScanner(f)
		for word.Scan() {
			var fiveonetwo = sha512Returner(word.Text())
			if fiveonetwo == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if one := sha1Returner(word.Text()); one == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if five := md5Returner(word.Text()); five == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if twofivesix := sha256Returner(word.Text()); twofivesix == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if bcryptChecker(hash.Text(), word.Text()) {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if threetwofivesix := sha3256Returner(word.Text()); threetwofivesix == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if mdfour := md4Returner(word.Text()); mdfour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if twotwofour := sha224Returner(word.Text()); twotwofour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if mdtwo := md2Returner(word.Text()); mdtwo == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if threeightfour := sha384Returner(word.Text()); threeightfour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if threethreeightfour := sha3384Returner(word.Text()); threethreeightfour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if threefiveonetwo := sha3512Returner(word.Text()); threefiveonetwo == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if threetwotwofour := sha3224Returner(word.Text()); threetwotwofour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if ripemdonesixzero := ripemd160Returner(word.Text()); ripemdonesixzero == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if ripemdonetwoeight := ripemd128Returner(word.Text()); ripemdonetwoeight == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if ripemdtwofivesix := ripemd256Returner(word.Text()); ripemdtwofivesix == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if ripemdthreetwozero := ripemd320Returner(word.Text()); ripemdthreetwozero == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if w := whirlpoolReturner(word.Text()); w == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if blake2bthreeightfour := blake2b384Returner(word.Text()); blake2bthreeightfour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if blake2btwofivesix := blake2b256Returner(word.Text()); blake2btwofivesix == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if blake2bfiveonetwo := blake2b512Returner(word.Text()); blake2bfiveonetwo == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if tiger1 := tigerReturner(word.Text()); tiger1 == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if tiger2 := tiger2Returner(word.Text()); tiger2 == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			} else if murmursixytyfour := murmur364(word.Text()); murmursixytyfour == hash.Text() {
				fmt.Printf("We have found %s : %s\n")
			} else if xxh := xxhashReturner(word.Text()); xxh == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				break
			}
		}
	}
}

func main() {
	if len(os.Args) == 4 {
		FileBruteForcer(os.Args[2], os.Args[3])
	} else if len(os.Args) == 3 {
		Bruteforcer(os.Args[1], os.Args[2])
	} else {
		fmt.Printf("Usage:\n%s <hash> <wordlistFilePath>\nor\n%s file <hashFilePath> <wordlistFilePath>", os.Args[0], os.Args[0])
	}
}
