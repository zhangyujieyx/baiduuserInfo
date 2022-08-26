package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrAppIDNotMatch       = errors.New("app_key not match")
	ErrInvalidBlockSize    = errors.New("invalid block size")
	ErrInvalidPKCS7Data    = errors.New("invalid PKCS7 data")
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

type BdUserInfo struct {
	OpenID     string `json:"open_id"`
	NickName   string `json:"nickname"`
	Sex        int    `json:"sex"`
	Headimgurl string `json:"headimgurl"`
	Mobile     string `json:"mobile"`
}

type BDUserDataCrypt struct {
	appKey, sessionKey string
}

func NewBDUserDataCrypt(appKey, sessionKey string) *BDUserDataCrypt {
	return &BDUserDataCrypt{
		appKey:     appKey,
		sessionKey: sessionKey,
	}
}

// 解除填充
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if len(data)%blockSize != 0 || len(data) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	plaintext := data
	c := data[len(data)-1]
	n := int(c)
	if n == 0 || n > len(data) {
		return nil, ErrInvalidPKCS7Padding
	}
	content := plaintext[:len(plaintext)-n]
	//去除header
	content = content[16:]
	//获取需要截取字符串的总长度
	var strLen = content[0:4]
	xmllen := binary.BigEndian.Uint32(strLen)
	//内容
	xmlcontent := content[4 : xmllen+4]
	//appkey
	//fromclientid := string(content[xmllen+4:])

	return xmlcontent, nil
}

func (w *BDUserDataCrypt) Decrypt(encryptedData, iv string) (*BdUserInfo, error) {
	aesKey, err := base64.StdEncoding.DecodeString(w.sessionKey)
	if err != nil {
		return nil, err
	}
	cipherText, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	ivBytes, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, ivBytes)
	mode.CryptBlocks(cipherText, cipherText)
	cipherText, err = pkcs7Unpad(cipherText, mode.BlockSize())
	fmt.Println("str:", string(cipherText))
	if err != nil {
		return nil, err
	}
	var userInfo BdUserInfo
	err = json.Unmarshal(cipherText, &userInfo)
	if err != nil {
		return nil, err
	}
	return &userInfo, nil
}



//示例---解密用户信息
func decryptUserInfo(sessionKey, iv, encryptedData string) *BdUserInfo {
	appKey := SmartProgram.AppKey
	decryption := NewBDUserDataCrypt(appKey, sessionKey)
	userInfo, err := decryption.Decrypt(encryptedData, iv)
	if err != nil {
		ErrLogger.Error("decrypt baidu userdata failed. err:%v", err)
		return nil
	}
	return userInfo
}
