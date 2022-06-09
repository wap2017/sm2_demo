package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/tjfoc/gmsm/x509"
)

func main() {
	cipherText := "abc"
	text, err := EncryptSM2([]byte(cipherText))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("加密后:", text)

	after, err := DecryptSM2(text)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("解密后", string(after))
}

func EncryptSM2(plainText []byte) (string, error) {
	//读取密钥对
	re := ``
	publicKeyFromPem, err := x509.ReadPublicKeyFromPem([]byte(re))
	if err != nil {
		return "", err
	}
	//3.加密
	cipherText, err := publicKeyFromPem.EncryptAsn1(plainText, rand.Reader)
	if err != nil {
		return "", err
	}
	cipherStr := hex.EncodeToString(cipherText)
	return cipherStr, nil
}

//解密
func DecryptSM2(cipherStr string) ([]byte, error) {
	//1.将pem格式私钥文件解码并反序列话
	re := ``
	privateKeyFromPem, err := x509.ReadPrivateKeyFromPem([]byte(re), nil)
	if err != nil {
		return nil, err
	}
	//2.解密
	bytes, _ := hex.DecodeString(cipherStr)
	planiText, err := privateKeyFromPem.DecryptAsn1(bytes)
	if err != nil {
		return nil, err
	}
	return planiText, nil
}
