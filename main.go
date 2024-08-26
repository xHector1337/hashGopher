package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
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

func Bruteforcer(text string) int {
	var file, err = os.Open("hello.txt")
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
	}
	return 1
}

func main() {
	var hash = md5Returner("hello")
	Bruteforcer(hash)
}
