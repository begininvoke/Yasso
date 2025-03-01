package plugin

import (
	"Yasso/config"
	"fmt"
	"net"
	"os"

	"github.com/masterzen/winrm"
)

func WinRMAuth(info config.ServiceConn, user, pass string) (*winrm.Client, bool, error) {
	var err error
	params := winrm.DefaultParameters
	// Set proxy authentication
	params.Dial = func(network, addr string) (net.Conn, error) {
		return net.DialTimeout("tcp", fmt.Sprintf("%s:%v", info.Hostname, info.Port), info.Timeout)
	}
	// Set input
	endpoint := winrm.NewEndpoint("other-host", 5985, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClientWithParameters(endpoint, user, pass, params)
	stdout := os.Stdout
	res, err := client.Run("echo ISOK > nul", stdout, os.Stderr)
	if err != nil {
		return nil, false, err
	}
	if res == 0 && err == nil {
		return client, true, nil
	}
	return nil, false, err
}
