package main

import (
	"log"
	"os"
	"strconv"

	"github.com/aeof/socks5"
)

func main() {
	users := map[string]string{
		"admin":    "123456",
		"zhangsan": "1234",
		"lisi":     "abde",
	}
	port := 7891
	if len(os.Args) > 1 {
		if val, err := strconv.Atoi(os.Args[1]); err == nil {
			port = val
		} else {
			log.Println("端口解析错误:" + os.Args[1])
		}
	}
	server := socks5.SOCKS5Server{
		// IP: "127.0.0.1",
		IP:   "0.0.0.0",
		Port: port,
		Config: &socks5.Config{
			AuthMethod: socks5.MethodNoAuth,
			PasswordChecker: func(username, password string) bool {
				wantPassword, ok := users[username]
				if !ok {
					return false
				}
				return wantPassword == password
			},
		},
	}

	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}
