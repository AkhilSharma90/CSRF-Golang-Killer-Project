package main

import (
	"log"
	"github.com/akhil/golang-csrf-project/db"
	"github.com/akhil/golang-csrf-project/server"
	"github.com/akhil/golang-csrf-project/server/middleware/myJwt"
)

var host = "localhost"
var port = "9000"

func main() {
	// init the DB
	db.InitDB()

	// init the JWTs
	jwtErr := myJwt.InitJWT()
	if jwtErr!= nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(jwtErr)
	}

	// start the server
	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting server!")
		log.Fatal(serverErr)
	}
}