# Wirego Remote in Python

## Working environment & commands

The `wirego` package is configured using [poetry](https://python-poetry.org/) and it should be installed as described in [official documentation](https://python-poetry.org/docs/).

Once you have `poetry` installed, these commands can be used to work with the project:

```bash
# Install required dependencies
poetry install

# Lint and format the package using ruff
poetry run ruff format
poetry run ruff check # optionally --fix to apply fixes automatically

# Run tests
# this will be done once tests are implemented

# Running examples
poetry run python3 examples/minimal/wirego_minimal.py
```

## Implementing own plugin based on Wirego Remote & running it

Full description of minimalistic implementation can be found in [examples/minimal/README](./examples/minimal/README.md), where all functions are described in detail.

To implement the plugin:

1. You should implement the `WiregoListener` abstract class, and as an example, you might refer to:

- `get_name` should return the protocol name, e.g. "eCPRI 2.0"
- `get_filter` should return the protocol filter, e.g. "ecpri"
- `get_fields` should return all fields that can be dissected by Wireshark
- `get_detection_filters` should return all "filters" to let Wireshark know which packets should be dissected by our dissector, e.g. `udp.port == 137` or `bluetooth.uuid == 1234`
- `get_detection_heuristics_parents` should return all protocols on top of which detection heuristic should be called
- `detection_heuristic` applies the heuristic to identify the protocol and returns whether the packet should be dissected by our dissector or not
- `dissect_packet` is the implementation of "parsing" the payload and assigning payload to fields

2. Use implemented `OurWiregoListener` and some ZMQ endpoint (e.g. `ipc:///tmp/wirego`) to instantiate `Wirego`. You may also use `wirego.results_cache_enable(boolean)` function to enable/disable cache.
3. Call `wirego.listen()` to start the plugin.
