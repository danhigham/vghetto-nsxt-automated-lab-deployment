package main

import (
	"fmt"
	"log"
	"flag"
	"net"
	"golang.org/x/crypto/ssh"
	"io"
	"strings"
)

var escapePrompt = []byte("localhost> ")

func main() {

	var mgmtThumb = flag.String("mgmt-thumb", "", "help message for flagname")
	var adminUser = flag.String("admin-user", "root", "")
	var adminPass = flag.String("admin-pass", "VMware1!", "")
	var mgmtIP = flag.String("nsx-mgmt-ip", "", "")
	var secret = flag.String("secret", "", "")
	
	var controllerIP = flag.String("nsx-ctrl-node", "", "")
	var nodesToRegister = flag.String("nsx-nodes", "", "")

	flag.Parse()

	sshConfig := &ssh.ClientConfig{
	User: *adminUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(*adminPass),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	cmds := []string{
		fmt.Sprintf("join management-plane %s username %s thumbprint %s password %s", *mgmtIP, *adminUser, *mgmtThumb, *adminPass),
		fmt.Sprintf("set control-cluster security-model shared-secret secret %s", *secret),
		fmt.Sprintf("initialize control-cluster"),
	}

	err, _ := executeCmd(cmds, *controllerIP, sshConfig)
	if (err != nil) {
		log.Panic(err)
	}

	nodes := strings.Split(*nodesToRegister, ",")
	for _, node := range nodes {
		cmds := []string {
			fmt.Sprintf("join management-plane %s username %s thumbprint %s password %s", *mgmtIP, *adminUser, *mgmtThumb, *adminPass),
			fmt.Sprintf("set control-cluster security-model shared-secret secret %s", *secret),
			"get control-cluster certificate thumbprint",
		}

		err, output := executeCmd(cmds, node, sshConfig)

		if (err != nil) {
			log.Panic(err)
		}

		thumbprint := strings.Replace(output[2], "prompt\n", "", 0)
	 	cmds = []string {
			fmt.Sprintf("join control-cluster %s thumbprint %s", node, thumbprint),
		}

		err, output = executeCmd(cmds, *controllerIP, sshConfig)

		if (err != nil) {
			log.Panic(err)
		}

	 	cmds = []string {
			fmt.Sprintf("activate control-cluster"),
		}

		err, output = executeCmd(cmds, node, sshConfig)

		if (err != nil) {
			log.Panic(err)
		}
	}
}

func executeCmd(cmd []string, hostname string, config *ssh.ClientConfig) (error, []string) {
    log.Printf("Connecting to %s\n", hostname)
	
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", hostname), config)
    if err != nil {
		return err, nil
    }

    defer client.Close()
    session, err := client.NewSession()

    if err != nil {
		return err, nil
    }
    defer session.Close()

    modes := ssh.TerminalModes{
        ssh.ECHO:          0,     // disable echoing
        ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
        ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
    }

    if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return err, nil
    }

    w, err := session.StdinPipe()
    if err != nil {
		return err, nil
    }
    r, err := session.StdoutPipe()
    if err != nil {
		return err, nil
    }
	
	if err := session.Start("/bin/nsxcli"); err != nil {
		return err, nil
    }

	var buffer []string
	readUntil(r, escapePrompt)
	
	for _, currentCmd := range cmd {
		log.Printf("Sending : %s\n", currentCmd)
		write(w, currentCmd)
		
		out, err := readUntil(r, escapePrompt)
		if err != nil {
			return err, nil
		}
		buffer = append(buffer, *out)
    	log.Printf("Received: %s\n", *out)
	}

    write(w, "exit")
    session.Wait()

	return nil, buffer
}

func write(w io.WriteCloser, command string) error {
    _, err := w.Write([]byte(command + "\n"))
    return err
}

func readUntil(r io.Reader, matchingByte []byte) (*string, error) {
    var buf [64 * 1024]byte
    var t int
    for {
        n, err := r.Read(buf[t:])
        if err != nil {
            return nil, err
        }
        t += n
        if isMatch(buf[:t], t, matchingByte) {
            stringResult := string(buf[:t])
            return &stringResult, nil
        }
    }
}

func isMatch(bytes []byte, t int, matchingBytes []byte) bool {
    if t >= len(matchingBytes) {
        for i := 0; i < len(matchingBytes); i++ {
            if bytes[t - len(matchingBytes) + i] != matchingBytes[i] {
                return false
            }
        }
        return true
    }
    return false
}
