# Migrating from Wirego v1 to v2

The migration from Wirego v1 to Wirego v2 is quite easy.

A few things have changed:

  - You code will not be loaded anymore as a dynamic library
  - The Setup inferface does not exist anymore
  - You don't need the "init()" function anymore
  - You need to implement the "main()" function
  - You need to explicitely initialize the wirego package by using **New**


## Step1: update

Edit your main function, which used to be empty, as follow:

    func main() {
      var wge WiregoSample

      wg, err := wirego.New("ipc:///tmp/wirego0", false, wge)
      if err != nil {
        fmt.Println(err)
        return
      }
      wg.ResultsCacheEnable(false)

      wg.Listen()
    }

You should edit on the above code snippet:

  - var wge WiregoSample 
  - wg.ResultsCacheEnable(false)

## Step 2: cleanup

Erase your init() and Setup functions.
If needed, move contents to the main function.

## Step 3: build

Build using:

    go build

## Step 4: running

When loading Wireshark, go to the Settings and update what used to be the plugin's library path, to the defined ZMQ endpoint (in the previous example: **"ipc:///tmp/wirego0"**).
Restart Wireshark.


