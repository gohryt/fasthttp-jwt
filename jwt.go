package jwt

import (
	"github.com/cristalhq/jwt/v5"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"

	"github.com/gohryt/asphyxia-core/bytes"
	"github.com/gohryt/asphyxia-core/random"
)

type (
	TokenGeneratorConfiguration struct {
		UserValueKey    string
		SignatureLength int
		Expires         int
	}

	Claims[T any] struct {
		jwt.RegisteredClaims

		Data T
	}

	innerTokenGenerator[T any] struct {
		signature []byte

		builder  *jwt.Builder
		verifier jwt.Verifier

		userValueKey string
	}
)

func TokenGenerator[T any](configuration TokenGeneratorConfiguration, signature bytes.Buffer) (tokenGenerator *innerTokenGenerator[T], err error) {
	if len(signature) == 0 {
		signature = random.Slice([]byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), configuration.SignatureLength)
	}

	signer, err := jwt.NewSignerHS(jwt.HS256, signature)
	if err != nil {
		return
	}

	builder := jwt.NewBuilder(signer)

	verifier, err := jwt.NewVerifierHS(jwt.HS256, signature)
	if err != nil {
		return
	}

	tokenGenerator = &innerTokenGenerator[T]{
		signature:    signature,
		builder:      builder,
		verifier:     verifier,
		userValueKey: configuration.UserValueKey,
	}

	return
}

func (tokenGenerator *innerTokenGenerator[T]) Handler(source fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(context *fasthttp.RequestCtx) {
		header := &context.Response.Header
		a := header.Peek(fasthttp.HeaderAuthorization)

		token, err := jwt.ParseNoVerify(a)
		if err != nil {
			context.SetStatusCode(fasthttp.StatusUnauthorized)
			context.SetBodyString(err.Error())
			return
		}

		err = tokenGenerator.verifier.Verify(token)
		if err != nil {
			context.SetStatusCode(fasthttp.StatusUnauthorized)
			context.SetBodyString(err.Error())
			return
		}

		claims := &Claims[T]{}

		err = json.Unmarshal(token.Claims(), claims)
		if err != nil {
			context.SetStatusCode(fasthttp.StatusUnauthorized)
			context.SetBodyString(err.Error())
			return
		}

		context.SetUserValue(tokenGenerator.userValueKey, claims)

		if source != nil {
			source(context)
		}
	}
}

func (tokenGenerator *innerTokenGenerator[T]) Generate(claims *Claims[T]) (token *jwt.Token, err error) {
	return tokenGenerator.builder.Build(claims)
}
