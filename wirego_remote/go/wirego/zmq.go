package wirego

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	zmq "github.com/go-zeromq/zmq4"
)

type ZMQCommand func(msg *zmq.Msg) error

// zmqSetup setups the ZMQ endpoint
func (wg *Wirego) zmqSetup() error {
	slog.Info("Setting up ZMQ endpoint to " + wg.zqmEndpoint)
	wg.zmqContext = context.Background()
	wg.zmqSocket = zmq.NewRep(wg.zmqContext, zmq.WithDialerRetry(time.Second), zmq.WithAutomaticReconnect(true))

	err := wg.zmqSocket.Listen(wg.zqmEndpoint)
	if err != nil {
		return err
	}

	return nil
}

// Listen listens for incoming ZMQ REQ and dispatches to defined REQ callbacks
func (wg *Wirego) Listen() {
	if wg.listener == nil {
		return
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		_ = <-sigc
		wg.logs.Warn("Stopping...")
		wg.zmqSocket.Close()
	}()

	dispatcher := make(map[string]ZMQCommand)

	//Utility commands, not dispatched to the Wirego plugin interface
	dispatcher["utility_ping"] = wg.processUtilityPing
	dispatcher["utility_get_version"] = wg.processUtilityVersion

	//ZMQ interface commands
	dispatcher["setup_get_plugin_name"] = wg.processSetupGetPluginName
	dispatcher["setup_get_plugin_filter"] = wg.processSetupGetPluginFilter
	dispatcher["setup_get_fields_count"] = wg.processSetupGetFieldsCount
	dispatcher["setup_get_field"] = wg.processSetupGetField
	dispatcher["setup_detect_int"] = wg.processSetupDetectInt
	dispatcher["setup_detect_string"] = wg.processSetupDetectString
	dispatcher["setup_detect_heuristic_parent"] = wg.processSetupDetectHeuristicParent
	dispatcher["process_heuristic"] = wg.processProcessHeuristic
	dispatcher["process_dissect_packet"] = wg.processProcessDissectPacket
	dispatcher["result_get_protocol"] = wg.processResultGetProtocol
	dispatcher["result_get_info"] = wg.processResultGetInfo
	dispatcher["result_get_fields_count"] = wg.processResultGetFieldsCount
	dispatcher["result_get_field"] = wg.processResultGetField
	dispatcher["result_release"] = wg.processResultRelease

	slog.Info("Ready, waiting for Wirego bridge commands.")

	for {
		msg, err := wg.zmqSocket.Recv()
		if err != nil {
			fmt.Println(err)
			return
		}
		if len(msg.Frames) == 0 {
			break
		}

		//Frame 0 contains the command. Get rid of trailing /x00 C-string
		cmd := getStringFromFrame(msg.Frames[0])
		cb, found := dispatcher[cmd]
		if !found {
			slog.Error("Received unknown command from Wirego bridge: '" + cmd + "'")
			wg.returnFailure(nil)
		} else {
			slog.Debug("Processing command '" + cmd + "'...")
			err = cb(&msg)
			if err != nil {
				slog.Warn("Command '" + cmd + "' failed:" + err.Error())
			}
		}
	}
	wg.logs.Info("Listen exitted")
}
