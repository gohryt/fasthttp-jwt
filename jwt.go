package JWT

import (
	"math/rand"
	"time"

	"github.com/bytedance/sonic"
	"github.com/cristalhq/jwt/v5"
	"github.com/valyala/fasthttp"
)

type (
	TokenGeneratorConfiguration struct {
		UserValueKey string `json:"user_value_key"`
		Expires      int    `json:"expires"`
	}

	TokenGeneratorParameters struct {
		ErrorHandler func(ctx *fasthttp.RequestCtx, err error)
		Signature    []byte
	}

	Claims[T any] struct {
		jwt.RegisteredClaims
		Data T
	}

	innerTokenGenerator[T any] struct {
		errorHandler func(ctx *fasthttp.RequestCtx, err error)
		signature    []byte

		builder  *jwt.Builder
		verifier jwt.Verifier

		userValueKey string
	}
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func signature(rand *rand.Rand) []byte {
	target := make([]byte, 512)

	for i := range target {
		target[i] = charset[rand.Intn(len(charset))]
	}

	return target
}

func Prepare[T any](configuration TokenGeneratorConfiguration, parameters TokenGeneratorParameters) (tokenGenerator *innerTokenGenerator[T], err error) {
	if parameters.ErrorHandler == nil {
		parameters.ErrorHandler = func(ctx *fasthttp.RequestCtx, err error) {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBodyString(err.Error())
		}
	}

	if len(parameters.Signature) == 0 {
		parameters.Signature = signature(rand.New(rand.NewSource(time.Now().UnixNano())))
	}

	signer, err := jwt.NewSignerHS(jwt.HS256, parameters.Signature)
	if err != nil {
		return
	}

	builder := jwt.NewBuilder(signer)

	verifier, err := jwt.NewVerifierHS(jwt.HS256, parameters.Signature)
	if err != nil {
		return
	}

	tokenGenerator = &innerTokenGenerator[T]{
		errorHandler: parameters.ErrorHandler,
		signature:    parameters.Signature,
		builder:      builder,
		verifier:     verifier,
		userValueKey: configuration.UserValueKey,
	}

	return
}

func (tokenGenerator *innerTokenGenerator[T]) Handler(source fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		authorization := ctx.Response.Header.Peek(fasthttp.HeaderAuthorization)

		token, err := jwt.ParseNoVerify(authorization)
		if err != nil {
			tokenGenerator.errorHandler(ctx, err)
			return
		}

		err = tokenGenerator.verifier.Verify(token)
		if err != nil {
			tokenGenerator.errorHandler(ctx, err)
			return
		}

		claims := new(Claims[T])

		err = sonic.Unmarshal(token.Claims(), claims)
		if err != nil {
			tokenGenerator.errorHandler(ctx, err)
			return
		}

		ctx.SetUserValue(tokenGenerator.userValueKey, claims)
		source(ctx)
	}
}

func (tokenGenerator *innerTokenGenerator[T]) Generate(claims *Claims[T]) (token *jwt.Token, err error) {
	return tokenGenerator.builder.Build(claims)
}
