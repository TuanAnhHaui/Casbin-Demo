package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AtExpires    int64
	RtExpires    int64
}

func HashPassword(pass *string) {
	bytePass := []byte(*pass)
	hPass, _ := bcrypt.GenerateFromPassword(bytePass, bcrypt.DefaultCost)
	*pass = string(hPass)
}

func ComparePassword(dbPass, pass string) bool {
	return bcrypt.CompareHashAndPassword([]byte(dbPass), []byte(pass)) == nil
}

//GenerateToken -> generates token
func GenerateToken(userid uint) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Hour * 3).Unix()
	td.RtExpires = (time.Now().Add(time.Hour * 24).Unix())

	var err error
	//Createing AccessToken
	atclaims := jwt.MapClaims{
		"exp":    td.AtExpires,
		"iat":    time.Now().Unix(),
		"userID": userid,
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atclaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	rtclaims := jwt.MapClaims{
		"exp":    td.RtExpires,
		"iat":    time.Now().Unix(),
		"userID": userid,
	}
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtclaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
}

//ValidateToken --> validate the given token
func ValidateToken(token string) (*jwt.Token, error) {

	//2nd arg function return secret key after checking if the signing method is HMAC and returned key is used by 'Parse' to decode the token)
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			//nil secret key
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})

}
