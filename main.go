package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
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
func sha3Returner(text string) string {
	var hash = sha3.New256()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}
func md4Returner(text string) string {
	var hash = md4.New()
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
		var three = sha3Returner(s.Text())
		if three == text {
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
			} else if three := sha3Returner(word.Text()); three == word.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if mdfour := md4Returner(word.Text()); mdfour == word.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if twotwofour := sha224Returner(word.Text()); twotwofour == word.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
			} else if mdtwo := md2Returner(word.Text()); mdtwo == word.Text() {
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
