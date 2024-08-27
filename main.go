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
	"github.com/htruong/go-md2"
	"golang.org/x/crypto/bcrypt"
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
func Bruteforcer(text string, path string) int {
	var file, err = os.Open(path)
	if err != nil {
		fmt.Printf("%s", err)
		return 1
	}
	defer file.Close()
	var s = bufio.NewScanner(file)

	for s.Scan() {
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
		}
		var ripemdonesixzero = ripemd160Returner(s.Text())
		if ripemdonesixzero == text {
			fmt.Printf("Found the password: %s", s.Text())
		}
		var ripemdonetwoeight = ripemd128Returner(s.Text())
		if ripemdonetwoeight == text {
			fmt.Printf("Found the password: %s", s.Text())
		}
		var ripemdtwofivesix = ripemd256Returner(s.Text())
		if ripemdtwofivesix == text {
			fmt.Printf("Found the password: %s", s.Text())
		}
		var ripemdthreetwozero = ripemd320Returner(s.Text())
		if ripemdthreetwozero == text {
			fmt.Printf("Found the password: %s", s.Text())
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
			} else if one := sha1Returner(word.Text()); one == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if five := md5Returner(word.Text()); five == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if twofivesix := sha256Returner(word.Text()); twofivesix == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if bcryptChecker(hash.Text(), word.Text()) {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if threetwofivesix := sha3256Returner(word.Text()); threetwofivesix == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if mdfour := md4Returner(word.Text()); mdfour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if twotwofour := sha224Returner(word.Text()); twotwofour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if mdtwo := md2Returner(word.Text()); mdtwo == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if threeightfour := sha384Returner(word.Text()); threeightfour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if threethreeightfour := sha3384Returner(word.Text()); threethreeightfour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if threefiveonetwo := sha3512Returner(word.Text()); threefiveonetwo == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if threetwotwofour := sha3224Returner(word.Text()); threetwotwofour == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if ripemdonesixzero := ripemd160Returner(word.Text()); ripemdonesixzero == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if ripemdonetwoeight := ripemd128Returner(word.Text()); ripemdonetwoeight == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if ripemdtwofivesix := ripemd256Returner(word.Text()); ripemdtwofivesix == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if ripemdthreetwozero := ripemd320Returner(word.Text()); ripemdthreetwozero == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
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
