package Security

import "errors"

var ErrJWTConfigAlreadySet = errors.New("jwt config is already set")
var ErrJWTConfigNotSet = errors.New("jwt config is not set")
var ErrJWTUnexpectedSigningMethod = errors.New("unexpected signing method")
var ErrJWTUnexpectedClaims = errors.New("unexpected token claims")
var ErrJWTInvalidToken = errors.New("invalid token")
var ErrJWTExpiredToken = errors.New("expired token")
