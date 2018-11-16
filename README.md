# CS-5700-Project-4

Authors:

Jason Teng: 001876580

Seung Son: 001894138

Jason Teng worked on developing the TCP wrapper/unwrapper, as well as the handshake and parsing the input. There was a lot of difficulty in calculating the TCP checksum correctly, both due to programmer error as well as confusion with network-order versus system-order encoding. Wireshark was helpful in determining where the checksum calculation was failing, as well as monitoring the connection status after the wrappers were completed. Our initial implementation for receiving packets was very naive, not buffering any packets at all, and dropping any packets which were not the next expected packet. This led to severely decreased performance on lossy networks, or if the system was slow, as was the case sometimes when running the program in a VM. 
