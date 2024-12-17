package wirego

import (
	"context"
	"fmt"
	"time"

	zmq "github.com/go-zeromq/zmq4"
)

type ZMQCommand func(msg *zmq.Msg) error

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

	dispatcher := make(map[string]ZMQCommand)

	//Utility commands, not dispatched to the Wirego plugin interface
	dispatcher["ping"] = wg.processPing
	dispatcher["version"] = wg.processVersion

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
		cb, found := dispatcher[cmd]
		if !found {
			fmt.Println("Unknown command: '" + cmd + "'")
		} else {
			fmt.Println("Processing command", cmd, "...")
			err = cb(&msg)
			if err != nil {
				fmt.Println("-> Failed:", err)
			} else {
				fmt.Println("-> Success.")
			}
		}
	}
}

func (wg *Wirego) processPing(msg *zmq.Msg) error {
	response := zmq.NewMsgFromString([]string{"echo reply\x00"})
	return wg.zmqSocket.Send(response)
}

func (wg *Wirego) processVersion(msg *zmq.Msg) error {
	response := zmq.NewMsgFrom([]byte{byte(WiregoVersionMajor)}, []byte{byte(WiregoVersionMinor)})
	return wg.zmqSocket.Send(response)
}
