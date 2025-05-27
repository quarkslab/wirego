# Wirego Remote in Rust

## Working environment & commands

As the first step - you surely need to install Rust and you should follow guides from [Rust Official page](https://www.rust-lang.org/). Once Rust is installed, use these commands:

```bash
# Build the application
cargo build # in `dev` profile [unoptimized + debuginfo]
cargo build --release # in `release` profile [optimized]

# Check the package and its dependencies for errors
cargo check # in `dev` profile
cargo check --release # in `release` profile

# Run unit and integration tests
cargo test
cargo test -- --nocapture # if you want to see the stdout/stderr
cargo llvm-cov --html # generate coverage report, more info here: https://github.com/taiki-e/cargo-llvm-cov

# Running examples
cargo run --example minimal
```

## Implementing own plugin based on Wirego Remote & running it

To implement the plugin, you may follow examples from the package. To have the plugin working, you have to:

1. implement `WiregoListener` trait:

- `get_name` should return the protocol name, e.g. "eCPRI 2.0"
- `get_filter` should return the protocol filter, e.g. "ecpri"
- `get_fields` should return all fields that can be returned by your Wireshark plugin
- `get_detection_filters` should return all "filters" to let Wireshark know which packets should be dissected by our dissector, e.g. `udp.port == 137` or `bluetooth.uuid == 1234`
- `get_detection_heuristics_parents` should return all protocols on top of which detection heuristic should be called
- `detection_heuristic` applies the heuristic to identify the protocol and returns whether the packet should be dissected by our dissector or not
- `dissect_packet` is the implementation of "parsing" the payload and assigning payload to fields

2. use implemented `OurWiregoListener` and some ZMQ endpoint (e.g. `ipc:///tmp/wirego`) to instantiate `Wirego`
3. call `wirego.listen().await` to start the plugin communication with Wirego Bridge

Assuming that you have done it and started the binary with `cargo run` (you may call `cargo run --example minimal` to use the minimal example which follows all steps described above), run Wireshark and open the PCAP. If you've configured everything well, you should see decoded payload by your plugin.

Sometimes the plugin may fail to bind the endpoint with "Address already in use" error - simply check what you bind your plugin to and remove that file (it works in case of IPC), e.g. `rm -rf /tmp/wirego`.

## Limitations

- Since the `wirego` uses ZMQ for communication and this crate uses `zeromq` (native implementation without C-bindings), there is no support for UDP communication. That means that if you want to use the plugin, you may use TCP or IPC on Linux, and TCP only on Windows.
