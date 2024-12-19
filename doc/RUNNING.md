# Setting up Wireshark and running


## Installing the Wirego plugin for Wireshark

Once you have built the Wirego plugin for Wireshark (or downloaded a pre-built version), you should have a Wireshark plugin named __wirego.so__.

Refer to the [Wireshark documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) to know where the plugin should be dropped.
You may also want to take a look at [https://www.wireshark.org/docs/wsug_html_chunked/ChConfigurationPluginFolders.html](https://www.wireshark.org/docs/wsug_html_chunked/ChConfigurationPluginFolders.html) which may give different hints.

Another option is to start Wireshark, open the "About" dialog, click on the "Folders" tab and search for the "Personal Plugins" entry:

![About](./img/about.png)


To make sure your plugin has been properly loaded, open Preferences>Protocols and search for "wirego".

If your golang plugin fails to load for any reason, the plugin will not appear on that list.


## Configuring your endpoint

Once the Wirego plugin for Wireshark is installed open Wireshark preferences, select "Protocols" on the left menu and then locate "Wirego".

Enter the endpoint to match the one used on you **Wirego remote plugin**.
