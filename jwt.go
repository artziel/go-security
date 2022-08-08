package Security

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

func CreateJWTToken(claims jwt.MapClaims, lifeSpan int, secret string) (string, error) {

	var err error
	//Creating Access Token
	claims["authorized"] = true
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(lifeSpan)).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := at.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return token, nil
}

func VerifyToken(tokenString string, secret string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func DecodeJWTToken(tokenString string, secret string) (*jwt.MapClaims, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrJWTUnexpectedSigningMethod
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	if token.Valid {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			return &claims, nil
		} else {
			return nil, ErrJWTUnexpectedClaims
		}
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, ErrJWTInvalidToken
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return nil, ErrJWTExpiredToken
		} else {
			return nil, errors.New("couldn't handle this Token: " + err.Error())
		}
	} else {
		return nil, errors.New("couldn't handle this Token: " + err.Error())
	}
}
