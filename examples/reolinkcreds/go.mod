module reolinkcreds

go 1.21.5

replace github.com/quarkslab/wirego/wirego => ../../wirego_remote/go

require github.com/quarkslab/wirego/wirego v0.0.0-20240401141356-ea0d385400fc

require (
	github.com/go-zeromq/goczmq/v4 v4.2.2 // indirect
	github.com/go-zeromq/zmq4 v0.17.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.15.0 // indirect
)
