import scapy.all as sc
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff on")
    parser.add_argument("-f", "--filter", dest="filter", help="Filter to apply to the sniffing")
    parser.add_argument("-o", "--output", dest="output", help="Output file for the sniffing")
    parser.add_argument("-s", "--show", action="store_true",dest="show", help="Show the sniffed packets")
    parser.add_argument("-v", "--verbose", action="store_true",dest="verbose", help="Verbose mode")
    options = parser.parse_args()
    return options

if __name__ == "__main__":
    options = get_arguments()
    if options.interface:
        interface = options.interface
    else:
        interface = sc.conf.iface
    if options.filter:
        filter = options.filter
    else:
        filter = None
    if options.output:
        output = options.output
    else:
        output = "output.pcap"
    if options.show:
        show = options.show
    else:
        show = False
    if options.verbose:
        verbose = options.verbose
    else:
        verbose = False
    sc.wrpcap(output, sc.sniff(iface=interface, filter=filter, prn=lambda x: x.summary() if show else None, store=1))
    if verbose:
        print("/nSniffing on interface %s with filter %s, output file %s" % (interface, filter, output))
