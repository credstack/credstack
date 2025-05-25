package main

import (
	"fmt"
	"github.com/stevezaluk/credstack-lib/options"
	"github.com/stevezaluk/credstack-lib/server"
	"github.com/stevezaluk/credstack-lib/user"
)

func validateHashes() {
	cred, err := user.NewCredential("Password", options.Credential())
	if err != nil {
		fmt.Println(err)
		return
	}

	err = user.ValidateSecret([]byte("Pasdddsword"), cred)
	fmt.Println(err)
}

func main() {
	dbOpts := &options.DatabaseOptions{
		Hostname:               "dev01.asgard-server.net",
		Port:                   27017,
		Username:               "dev01_mongo_admin",
		Password:               "Kgy.oV.uQ6wFfe9N4oE*PBys",
		DefaultDatabase:        "dev_credstack",
		AuthenticationDatabase: "admin",
		UseAuthentication:      true,
	}

	serv := server.New(dbOpts, options.Log())

	err := serv.Database().Connect()
	if err != nil {
		fmt.Println("connect error: ", err)
		return
	}

	//err = user.RegisterUser(serv, options.Credential(), "testing@gmail.com", "testing", "Password123456789")
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}

	model, err := user.GetUser(serv, "testing@.com", false)
	if err != nil {
		fmt.Println("get user error ", err)

		return
	}

	fmt.Println("Fetched model: ", model)

	//err = user.DeleteUser(serv, "testing@gmail.com")
	//if err != nil {
	//	fmt.Println("delete user error ", err)
	//  return
	//}

	//validateHashes()

	err = serv.Database().Disconnect()
	fmt.Println("disconnecting from db: ", err)
}
