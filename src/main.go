package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/dgrijalva/jwt-go"
)

var (
	AwsRegion    string
	UserPoolId   string
	AccountId    string
	ApiGatewayId string
)

func main() {
	AwsRegion = assertEnv("REGION")
	UserPoolId = assertEnv("USER_POOL_ID")
	AccountId = assertEnv("ACCOUNT_ID")
	ApiGatewayId = assertEnv("API_GATEWAY_ID")

	lambda.Start(HandleRequest)
}

func assertEnv(env string) string {
	value, present := os.LookupEnv(env)
	if !present {
		log.Fatalf("Error with ENV variable '%s' not set", env)
	}
	return value
}

type MyCustomClaims struct {
	Data string `json:"data"`
	jwt.StandardClaims
}

type Response struct {
	Token string `json:"token"`
}

type CognitoWellKnownResponse struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type JWK struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

func decodeJWKs(jwksJSON string) ([]JWK, error) {
	var jwks struct {
		Keys []JWK `json:"keys"`
	}
	err := json.Unmarshal([]byte(jwksJSON), &jwks)
	if err != nil {
		return nil, err
	}
	return jwks.Keys, nil
}

func fetchJWKS() (string, error) {
	resp, err := http.Get(fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", AwsRegion, UserPoolId))
	if err != nil {
		return "", fmt.Errorf("failed to make the GET request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read the response body: %w", err)
	}
	return string(body), nil
}

func getPublicKey(keys []JWK, kid string) (*rsa.PublicKey, error) {
	for _, key := range keys {
		if key.Kid == kid && key.Kty == "RSA" {
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, err
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, err
			}
			return &rsa.PublicKey{
				N: big.NewInt(0).SetBytes(nBytes),
				E: int(big.NewInt(0).SetBytes(eBytes).Int64()),
			}, nil
		}
	}
	return nil, fmt.Errorf("public key not found for kid: %s", kid)
}

func generateAuthzResponse(principalId string, statements []events.IAMPolicyStatement) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalId}
	authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
		Version:   "2012-10-17",
		Statement: statements,
	}
	return authResponse
}

func generateStatement(action, effect, resource string) events.IAMPolicyStatement {
	return events.IAMPolicyStatement{
		Action:   []string{action},
		Effect:   effect,
		Resource: []string{resource},
	}
}

func HandleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	authToken := event.AuthorizationToken
	fmt.Printf("Token: %s\n", authToken)
	method := event.MethodArn
	fmt.Printf("Method ARN: %s\n", method)
	eType := event.Type
	fmt.Printf("Event type: %s\n", eType)

	denyStatements := []events.IAMPolicyStatement{
		generateStatement("execute-api:Invoke", "Deny", method),
	}
	denyResponse := generateAuthzResponse("user", denyStatements)
	if authToken == "" {
		denyResponse.Context = map[string]interface{}{
			"message": "missing Authorization header",
		
		}
		return denyResponse, errors.New("missing Authorization header")
	}
	authHeaderParts := strings.Split(authToken, "Bearer ")
	if len(authHeaderParts) != 2 {
		denyResponse.Context = map[string]interface{}{
			"message": "invalid token format",
		}
		return denyResponse, errors.New("invalid token format")
	}
	tokenStr := authHeaderParts[1]
	//jwksJSON, err := fetchJWKS()
	//if err != nil {
	//	denyResponse.Context = map[string]interface{}{
	//		"message": err,
	//	}
	//	return denyResponse, fmt.Errorf("error fetching JWKS: %w", err)
	//}
	//keys, err := decodeJWKs(jwksJSON)
	//if err != nil {
	//	denyResponse.Context = map[string]interface{}{
	//		"message": err,
	//	}
	//	return denyResponse, fmt.Errorf("error decoding JWKS: %w", err)
	//}
	//token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
	//	// Verify the signing method
	//	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
	//		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	//	}
	//
	//	// Provide the public key for verification
	//	kid := token.Header["kid"].(string)
	//	publicKey, err := getPublicKey(keys, kid)
	//	if err != nil {
	//		return nil, err
	//	}
	//	return publicKey, nil
	//})
	//
	//if err != nil {
	//	denyResponse.Context = map[string]interface{}{
	//		"message": err,
	//	}
	//	return denyResponse, fmt.Errorf("error decoding JWTs: %w", err)
	//}
	//if !token.Valid {
	//	denyResponse.Context = map[string]interface{}{
	//		"message": "Invalid JWT token",
	//	}
	//	return denyResponse, fmt.Errorf("invalid JWT token")
	//}
	//println(token.Claims)

	if tokenStr != "trust me bro" {
		denyResponse.Context = map[string]interface{}{
			"message": "invalid passphrase",
		}
		return denyResponse, errors.New("Unauthorized")
	}

	statements := []events.IAMPolicyStatement{
		generateStatement("execute-api:Invoke", "Allow", buildApiResource("*", "*", "*")),
	}
	return generateAuthzResponse("user", statements), nil
}

// arn:aws:execute-api:eu-central-1:275127660632:a23ypr2qzg/*/*/devices/{device.id for device in user.devices}/*

func buildApiResource(stage, method, path string) string {
	base := fmt.Sprintf("arn:aws:execute-api:%s:%s:%s", AwsRegion, AccountId, ApiGatewayId)
	return fmt.Sprintf("%s/%s/%s/%s", base, stage, method, path)
}

