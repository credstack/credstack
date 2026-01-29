module github.com/credstack/credstack/cli

go 1.25.5

replace github.com/credstack/credstack/apiclient v1.3.7-beta => ../apiclient

require github.com/spf13/cobra v1.10.2

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
)
