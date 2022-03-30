package producer

import (
	"net/http"
	"time"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/free5gc/http_wrapper"
	nrf_context "github.com/free5gc/nrf/context"
	"github.com/free5gc/nrf/logger"
	"github.com/free5gc/openapi/models"
)

func HandleAccessTokenRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// Param of AccessTokenRsp
	logger.AccessTokenLog.Infoln("Handle AccessTokenRequest")

	accessTokenReq := request.Body.(models.AccessTokenReq)

	response, errResponse := AccessTokenProcedure(accessTokenReq)

	if response != nil {
		// status code is based on SPEC, and option headers
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if errResponse != nil {
		return http_wrapper.NewResponse(http.StatusBadRequest, nil, errResponse)
	}
	problemDetails := &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}


func AccessTokenProcedure(request models.AccessTokenReq) (response *models.AccessTokenRsp,
	func NewJWT(privateKey []byte, publicKey []byte) JWT {
		return JWT{
			privateKey: privateKey,
			publicKey:  publicKey,
		}
	}
	errResponse *models.AccessTokenErr) {
	logger.AccessTokenLog.Infoln("In AccessTokenProcedure")
	type JWT struct {
	privateKey []byte
	publicKey  []byte
	}
	
	prvKey, err := ioutil.ReadFile("./support/TLS/NRF.key")
	if err != nil {
		log.Fatalln(err)
	}
	logger.AccessTokenLog.Infoln("Loaded NRF PVT Key")
	pubKey, err := ioutil.ReadFile("./suuport/TLS/NRF.pub")
	if err != nil {
		log.Fatalln(err)
	}
	logger.AccessTokenLog.Infoln("Exiting NRF Key loading")


	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	var expiration int32 = 1000
	scope := request.Scope
	tokenType := "Bearer"
	now := int32(time.Now().Unix())

	// Create AccessToken
	accessTokenClaims := models.AccessTokenClaims{
		Iss:            nrf_context.Nrf_NfInstanceID, // TODO: NF instance id of the NRF
		Sub:            request.NfInstanceId,         // nfInstanceId of service consumer
		Aud:            request.TargetNfInstanceId,   // nfInstanceId of service producer
		Scope:          request.Scope,                // TODO: the name of the NF services for which the
		Exp:            now + expiration,             // access_token is authorized for use
		StandardClaims: jwt.StandardClaims{},
	}
	accessTokenClaims.IssuedAt = int64(now)
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, accessTokenClaims)
	if err != nil {
		return "", fmt.Errorf("RSA Token generation failed: %w", err)
	}
	accessToken, err := token.SignedString(key)
	if err != nil {
		logger.AccessTokenLog.Warnln("RSA Token signature failed: %w", err)
		errResponse = &models.AccessTokenErr{
			Error: "invalid_request",
		}

		return nil, errResponse
	}

	response = &models.AccessTokenRsp{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   expiration,
		Scope:       scope,
	}

	return response, nil
}
