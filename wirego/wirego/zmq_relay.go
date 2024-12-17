package wirego

import (
	"context"
	"fmt"
	"time"

	zmq "github.com/go-zeromq/zmq4"
)

const (
	WiregoVersionMajor = 2
	WiregoVersionMinor = 0
)

func (wg *Wirego) zmqSetup() error {
	wg.zmqContext = context.Background()
	wg.zmqSocket = zmq.NewRep(wg.zmqContext, zmq.WithDialerRetry(time.Second))

	err := wg.zmqSocket.Listen(wg.zqmEndpoint)
	if err != nil {
		return err
	}

	return nil
}

func (wg *Wirego) Listen() {
	for {
		fmt.Println("Wait...")

		msg, err := wg.zmqSocket.Recv()
		if err != nil {
			fmt.Println(err)
			return
		}
		if len(msg.Frames) == 0 {
			continue
		}

		//Frame 0 contains the command. Get rid of trailing /x00 C-string
		cmd := string(msg.Frames[0][:len(msg.Frames[0])-1])
		switch cmd {
		case "ping":
			err = wg.processPing(&msg)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("Response sent")
			}
		case "version_major":
			err = wg.processVersionMajor(&msg)
			if err != nil {
				fmt.Println(err)
			}
		case "version_minor":
			err = wg.processVersionMinor(&msg)
			if err != nil {
				fmt.Println(err)
			}
		default:
			fmt.Println("Unknown command: '" + cmd + "'")
		}
		fmt.Println(msg.String())
		fmt.Println(cmd)
	}
}

func (wg *Wirego) processPing(msg *zmq.Msg) error {
	response := zmq.NewMsgFromString([]string{"echo reply\x00"})
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processVersionMajor(msg *zmq.Msg) error {
	response := zmq.NewMsg([]byte{byte(WiregoVersionMajor)})
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processVersionMinor(msg *zmq.Msg) error {
	response := zmq.NewMsg([]byte{byte(WiregoVersionMinor)})
	return wg.zmqSocket.Send(response)
}
