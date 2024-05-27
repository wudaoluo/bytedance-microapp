package apis

import (
	"encoding/base64"
	"encoding/json"
	"github.com/cute-angelia/go-utils/utils/encrypt/aes"
)

func DecryptUserInfo(encryptedData, sessionKey, iv string) DecryptUserInfoResp {
	src, _ := base64.StdEncoding.DecodeString(encryptedData)
	_key, _ := base64.StdEncoding.DecodeString(sessionKey)
	_iv, _ := base64.StdEncoding.DecodeString(iv)

	iaes, _ := aes.NewAesPackage(_key)
	result := iaes.DecryptCBC(src, _iv, aes.PaddingPkcs7).ToString()

	var resp DecryptUserInfoResp
	json.Unmarshal([]byte(result), &resp)
	return resp
}

// 获取手机号 和获取用户基本信息 是2个不同的功能，都放在一个结构体了
type DecryptUserInfoResp struct {
	NickName        string `json:"nickName"`
	AvatarUrl       string `json:"avatarUrl"`
	Gender          int    `json:"gender"`   // 用户性别，0: 未知；1:男性；2:女性
	City            string `json:"city"`     // 用户所在城市
	Province        string `json:"province"` // 用户所在省份
	Country         string `json:"country"`  //	用户所在国家
	OpenId          string `json:"openId"`   //	用户 openId
	CountryCode     string `json:"countryCode"`
	PhoneNumber     string `json:"phoneNumber"`
	PurePhoneNumber string `json:"purePhoneNumber"`
	Watermark       struct {
		Appid     string `json:"appid"`
		Timestamp int    `json:"timestamp"`
	} //敏感数据水印
}
