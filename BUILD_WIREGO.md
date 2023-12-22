# Building the Wirego plugin

## Manually

If you don't plan to use a pre-built version of the wirego plugin, you can built it manually.

Clone Wireshark:

    git clone https://github.com/wireshark/wireshark.git

Create a symlink from the Wireshark plugins folder to the "wirego_plugin"

    ln -s <path_to>/wirego_plugin wireshark/plugins/epan/wirego

Edit Wireshark's main CMakelists.txt and add the following to PLUGIN_SRC_DIRS:

    plugins/epan/wirego

Now build Wireshark (see README.xxx), but basically it's just:

    mkdir build && cd build
    cmake ../
    make -j

You may also just build the Wirego plugin (and now the full Wireshark program):

    mkdir build && cd build
    cmake -DBUILD_wireshark=OFF -DCUSTOM_PLUGIN_SRC_DIR=../../wireshark/plugins/epan/wirego ..
    make wirego

__Note:__ If cmake command fails and complains about an unknown "add_wireshark_plugin_library" command, replace it with "add_wireshark_epan_plugin_library" (prior version 4.2, this CMake command has been renamed).

## Using Docker

Use the following Dockerfile:

    FROM golang:latest

    # Install build tools and Wireshark dependencies
    RUN DEBIAN_FRONTEND=noninteractive apt update && apt -y install git build-essential cmake libgcrypt-dev qt6-base-dev qt6-multimedia-dev qt6-tools-dev qt6-tools-dev-tools qt6-l10n-tools libqt6core5compat6-dev libpcap-dev libgcrypt20-dev libglib2.0-dev flex bison libpcre2-dev libnghttp2-dev libc-ares-dev libspeexdsp-dev
    # Take a fresh version of Wireshark
    RUN git clone https://gitlab.com/wireshark/wireshark.git
    # Take a fresh version of Wirego
    RUN git clone https://github.com/quarkslab/wirego.git
    # Link the wirego plugin folder to the Wireshark plugins source folder
    RUN ln -s /go/wirego/wirego_plugin /go/wireshark/plugins/epan/wirego
    # Build Wireshark and plugins
    RUN cd /go/wireshark && git checkout release-4.2 && mkdir build && cd build && cmake -DCUSTOM_PLUGIN_SRC_DIR=/go/wireshark/plugins/epan/wirego .. && make


    # Build the example plugin
    RUN cd /go/wirego/wirego/example/ && make

Build the Docker image using:

    docker build . -t wiregobuild

Extract the built files from the image:

    id=$(docker create wiregobuild)
    docker cp $id:/go/wirego/wirego/example/wirego_example.so - > wirego_example.so.tar
    docker cp $id:/go/wireshark/build/run/wireshark - > wireshark.so.tar
    docker cp $id:./wireshark/build/run/plugins/4.2/epan/wirego.so - > wirego.so.tar        
    docker rm -v $id