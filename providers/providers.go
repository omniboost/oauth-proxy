package providers

type Providers []Provider

type Provider interface {
	Route() string
}
