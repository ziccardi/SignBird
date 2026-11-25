package main

import (
	"os"

	"signbird/key-certificate-service/internal/keycert"
)

func main() {
	keycert.Run(os.Args[1:])
}
