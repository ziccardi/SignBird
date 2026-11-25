package main

import (
	"os"

	"github.com/ziccardi/SignBird/key-certificate-service/internal/keycert"
)

func main() {
	keycert.Run(os.Args[1:])
}
