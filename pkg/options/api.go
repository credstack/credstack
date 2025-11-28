package options

type ApiOptions struct {
	// Port - The port number that the API should listen for requests on
	Port int

	// Debug - Enables debug logging for the API. Useful for development
	Debug bool

	// Prefork - Allows the API to run on multiple processes to increase performance
	Prefork bool

	// Will eventually support TLS options
}

/*
SetPort - Defines the port number that the API should listen for requests on
*/
func (opts *ApiOptions) SetPort(port int) *ApiOptions {
	opts.Port = port

	return opts
}

/*
SetDebug - If set to true, debug logging will be enabled and the following Fiber options are configured:

EnablePrintRoutes -> True
CaseSensitive -> False
StrictRouting -> False
IdleTimeout -> 10 mins
TrustProxy -> False
EnablePrefork -> False
*/
func (opts *ApiOptions) SetDebug(value bool) *ApiOptions {
	opts.Debug = value

	return opts
}

/*
SetPrefork - If set to true, then API will be run against multiple processes. Use this in production, performance
sensitive environments. If Debug is set to true, then this value is ignored.
*/
func (opts *ApiOptions) SetPrefork(value bool) *ApiOptions {
	opts.Prefork = value

	return opts
}
