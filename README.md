# Packet sniffer in Python

## What is packet sniffing?
![Sniffing](https://cyberhoot.com/wp-content/uploads/2020/02/Diagram-SNIFFER-2-1024x427-1.jpg)

Packet sniffers are applications or utilities that read data packets traversing the network within the Transmission Control Protocol/Internet Protocol (TCP/IP) layer. When in the hands of network administrators, these tools “sniff” internet traffic in real-time, monitoring the data, which can then be interpreted to evaluate and diagnose performance problems within servers, networks, hubs and applications.

When packet sniffing is used by hackers to conduct unauthorized monitoring of internet activity, network administrators can use one of several methods for detecting sniffers on the network. Armed with this early warning, they can take steps to protect data from illicit sniffers.

## How do hackers use packet sniffing?

Hackers will typically use one of two different methods of sniffing to surreptitiously monitor a company’s network. In the case of organizations with infrastructure configured using hubs that connect multiple devices together on a single network, hackers can utilize a sniffer to passively “spy” on all the traffic flowing within the system. Passive sniffing, such as this, is extremely difficult to uncover.

When a much larger network is involved, utilizing numerous connected computers and network switches to direct traffic only to specific devices, passive monitoring simply won’t provide access to all network traffic. In such a case, sniffing won’t be helpful for either legitimate or illegitimate purposes. Hackers will be forced to bypass the constraints created by the network switches. This requires active sniffing, which adds further traffic to the network, and in turn makes it detectable to network security tools.

## How does this project work?
There are several command line arguments to have different results:
* -i / --interface: Define the interface to sniff on.
* -f / --filter: Filter to apply to the sniffing.
* -o / --output: Define the name of the output file.
* -s / --show: Show the sniffed packets in terminal.
* -v / --verbose: Verbose mode.

A sample output while connecting google.com is as follows:

![Output](https://i.imgur.com/U37EOYp.png)

# Installation

Paste the following code to your terminal of choice in whichever directory you want:
`git clone https://github.com/hennastone/packet-sniffer-python.git`

That's it, run the sniffer.py connect to any network and sniff every data transmission.





