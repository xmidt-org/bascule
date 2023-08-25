package bascule

type Authorizer[T Token] interface {
	Authorize(resource any, token T) error
}
