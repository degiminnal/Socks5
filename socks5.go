package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

var (
	ErrVersionNotSupported       = errors.New("protocol version not supported")
	ErrMethodVersionNotSupported = errors.New("sub-negotiation method version not supported")
	ErrCommandNotSupported       = errors.New("requst command not supported")
	ErrInvalidReservedField      = errors.New("invalid reserved field")
	ErrAddressTypeNotSupported   = errors.New("address type not supported")
	ErrConnectionRefused         = errors.New("connection refused")
)

const (
	SOCKS5Version = 0x05
	ReservedField = 0x00
)

type Server interface {
	Run() error
}

type SOCKS5Server struct {
	IP     string
	Port   int
	Config *Config
}

type Config struct {
	AuthMethod      Method
	PasswordChecker func(username, password string) bool
}

func initConfig(config *Config) error {
	if config.AuthMethod == MethodPassword && config.PasswordChecker == nil {
		return ErrPasswordCheckerNotSet
	}
	return nil
}

func (s *SOCKS5Server) Run() error {
	// Initialize server configuration
	if err := initConfig(s.Config); err != nil {
		return err
	}

	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	log.Printf("listening: %v", address)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("connection failure from %s: %s", conn.RemoteAddr(), err)
			continue
		}

		go func() {
			defer conn.Close()
			log.Printf("source:%s", conn.RemoteAddr())
			err := handleConnection(conn, s.Config)
			if err != nil {
				log.Printf("handle connection failure from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConnection(conn net.Conn, config *Config) error {
	// 协商过程
	if err := auth(conn, config); err != nil {
		return err
	}

	// 请求过程
	targetConn, err := request(conn)
	if err != nil {
		return err
	}

	// 转发过程
	return forward(conn, targetConn)
}

func forward(conn io.ReadWriteCloser, targetConn io.ReadWriteCloser) error {
	var wg sync.WaitGroup
	wg.Add(2)
	defer conn.Close()
	defer targetConn.Close()
	go func() {
		io.Copy(targetConn, conn)
		wg.Done()
	}()
	go func() {
		io.Copy(conn, targetConn)
		wg.Done()
	}()
	wg.Wait()
	return nil
}

func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	var address string
	var targetConn io.ReadWriteCloser
	message, err := NewClientRequestMessage(conn)
	if err != nil {
		return nil, err
	}
	if message.AddrType == TypeIPv4 {
		address = fmt.Sprintf("%s:%d", message.Address, message.Port)
	} else if message.AddrType == TypeIPv6 {
		address = fmt.Sprintf("[%s]:%d", message.Address, message.Port)
	} else if message.AddrType == TypeDomain {
		ips, err := net.LookupIP(message.Address)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("IP地址解析失败:%s", message.Address)
		}
		ip := ips[0]
		if len(ip) == IPv4Length {
			address = fmt.Sprintf("%s:%d", ips[0], message.Port)
		} else if len(ip) == IPv6Length {
			address = fmt.Sprintf("[%s]:%d", ips[0], message.Port)
		}
	} else {
		return nil, ErrAddressTypeNotSupported
	}

	log.Printf("target: %v\n", address)

	switch message.Cmd {
	case CmdConnect:
		targetConn, err = requestConnect(address, conn)
		if err != nil {
			return nil, err
		}
	case CmdBind:
		return nil, errors.New("CmdBind not support yet")
	case CmdUDP:
		targetConn, err = requestUDP(address, conn)
		if err != nil {
			return nil, err
		}
	}
	return targetConn, nil
}

func requestUDP(address string, conn io.ReadWriter) (io.ReadWriteCloser, error) {
	// 请求访问目标TCP服务
	targetConn, err := net.Dial("udp", address)
	if err != nil {
		log.Println(err.Error())
		WriteRequestFailureMessage(conn, ReplyConnectionRefused)
		return nil, ErrConnectionRefused
	}

	// Send success reply
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.UDPAddr)
	return targetConn, WriteRequestSuccessMessage(conn, addr.IP, uint16(addr.Port))
}

func requestConnect(address string, conn io.ReadWriter) (io.ReadWriteCloser, error) {
	// 请求访问目标TCP服务
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		log.Println(err.Error())
		WriteRequestFailureMessage(conn, ReplyConnectionRefused)
		return nil, ErrConnectionRefused
	}

	// Send success reply
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.TCPAddr)
	return targetConn, WriteRequestSuccessMessage(conn, addr.IP, uint16(addr.Port))
}

func auth(conn io.ReadWriter, config *Config) error {
	// Read client auth message
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}

	// Check if the auth method is supported
	var acceptable bool
	for _, method := range clientMessage.Methods {
		if method == config.AuthMethod {
			acceptable = true
		}
	}
	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method not supported")
	}
	if err := NewServerAuthMessage(conn, config.AuthMethod); err != nil {
		return err
	}

	if config.AuthMethod == MethodPassword {
		cpm, err := NewClientPasswordMessage(conn)
		if err != nil {
			return err
		}

		if !config.PasswordChecker(cpm.Username, cpm.Password) {
			WriteServerPasswordMessage(conn, PasswordAuthFailure)
			return ErrPasswordAuthFailure
		}

		if err := WriteServerPasswordMessage(conn, PasswordAuthSuccess); err != nil {
			return err
		}
	}

	return nil
}
