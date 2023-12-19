# Building the Wirego plugin

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