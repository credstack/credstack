package options

type DatabaseOptions struct {
}

/*
Database - Returns a DatabaseOptions structure with some sensible defaults
*/
func Database() *DatabaseOptions {
	return &DatabaseOptions{}
}
