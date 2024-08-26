package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/bcrypt"
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

func sha512Returner(text string) string {
	var hash = sha512.New()
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
	}
	fmt.Println("We couldn't find anything.")
	return 1
}

func FileBruteForcer(path string, wordlist string) int {
	var f, err = os.Open(wordlist)
	if err != nil {
		fmt.Printf("%v", err)
		return 1
	}
	defer f.Close()
	var h, err1 = os.Open(path)
	if err1 != nil {
		fmt.Println(err1)
		return 1
	}
	defer h.Close()
	var word = bufio.NewScanner(f)
	var hash = bufio.NewScanner(h)
	for hash.Scan() {
		for word.Scan() {
			var fiveonetwo = sha512Returner(word.Text())
			if fiveonetwo == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				return 0
			}
			var one = sha1Returner(word.Text())
			if one == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				return 0
			}
			var five = md5Returner(word.Text())
			if five == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				return 0
			}
			var twofivesix = sha256Returner(word.Text())
			if twofivesix == hash.Text() {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				return 0
			}
			if bcryptChecker(hash.Text(), word.Text()) {
				fmt.Printf("We have found %s : %s\n", hash.Text(), word.Text())
				return 0
			}
		}
	}
	fmt.Printf("We couldn't find anything.\n")
	return 1
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
