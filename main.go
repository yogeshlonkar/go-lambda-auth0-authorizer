package main

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/golang-jwt/jwt/v4"
)

func main() {
	log.Println("Running lambda-authorizer")
	lambda.Start(handler)
}

func handler(request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	// split `bearer token` from Authorization header received in event.
	tokenSlice := strings.Split(request.AuthorizationToken, " ")
	var bearerToken string
	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	}

	// if no bearer token set return unauthorized.
	if bearerToken == "" {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("unauthorized")
	}

	jwks, err := fetchJWKS()
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, err
	}

	// Parse takes the token string using function to looking up the key.
	token, err := jwt.Parse(bearerToken, jwks.KeyFunc)
	if err != nil {
		if verr, ok := err.(*jwt.ValidationError); ok {
			if verr.Errors == jwt.ValidationErrorMalformed {
				return events.APIGatewayCustomAuthorizerResponse{}, errors.New("unauthorized")
			}
			if verr.Errors == jwt.ValidationErrorExpired {
				return events.APIGatewayCustomAuthorizerResponse{}, errors.New("token is expired")
			}
		}
		return events.APIGatewayCustomAuthorizerResponse{}, err
	}

	// handle nil token scenario, unlikely to happen.
	if token == nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("no token after JWT parsing")
	}

	// check if claims are present and token is valid.
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// return Allow authResponse with userEntity in authorizer context for next lambda in chain.
		return authPolicyResponse("user", "Allow", request.MethodArn, map[string]interface{}{"userEntity": claims["sub"].(string)}), nil
	}
	// default response which shouldn't be reached.
	return events.APIGatewayCustomAuthorizerResponse{}, errors.New("could not validate Token")
}

// fetchJWKS using github.com/MicahParks/keyfunc which has KeyFunc required for token parsing.
func fetchJWKS() (*keyfunc.JWKs, error) {
	refreshInterval := time.Hour
	refreshRateLimit := time.Minute * 5
	refreshTimeout := time.Second * 10
	refreshUnknownKID := true
	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError:%s\n", err.Error())
		},
		RefreshInterval:   &refreshInterval,
		RefreshRateLimit:  &refreshRateLimit,
		RefreshTimeout:    &refreshTimeout,
		RefreshUnknownKID: &refreshUnknownKID,
	}
	return keyfunc.Get("https://<YOUR-AUTH-DOMAIN>/.well-known/jwks.json", options)
}

// authPolicyResponse for authorization/ de-authorization of given principal with supplied context
func authPolicyResponse(principalID, effect, resource string, context map[string]interface{}) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalID}
	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}
	authResponse.Context = context
	return authResponse
}
