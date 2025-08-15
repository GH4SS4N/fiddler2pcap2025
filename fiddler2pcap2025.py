#!/usr/bin/env python3
import random
import os
import sys
import re
import zipfile
import tempfile
import shutil
from xml.dom.minidom import parse
from scapy.utils import PcapWriter
from scapy.all import IP, TCP, Raw
import glob
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-i", dest="input_target", type="string",
                  help="path to fiddler raw directory or sautez file (.saz)")
parser.add_option("-o", dest="output_pcap", type="string", help="output PCAP file")
parser.add_option("--src", dest="srcip", type="string", help="override src ip")
parser.add_option("--dst", dest="dstip", type="string", help="override dst ip")
parser.add_option("--dproxy", dest="dproxy", action="store_true", default=False,
                  help="attempt to unproxify the pcap")
parser.add_option("--saz", dest="input_is_saz", action="store_true", default=False,
                  help="input is .saz archive")

src = None
dst = None

def validate_ip(ip):
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):
        return True
    print(f"The IP address provided is invalid: {ip}")
    sys.exit(-1)

(options, args) = parser.parse_args()

if not options.input_target or not options.output_pcap:
    parser.print_help()
    sys.exit(-1)

if options.srcip and validate_ip(options.srcip):
    src = options.srcip
if options.dstip and validate_ip(options.dstip):
    dst = options.dstip

pktdump = PcapWriter(options.output_pcap, sync=True)

def build_handshake(src, dst, sport, dport):
    c_isn = random.randint(1024, 10000)
    s_isn = random.randint(1024, 10000)
    syn = IP(src=src, dst=dst)/TCP(flags="S", sport=sport, dport=dport, seq=c_isn)
    synack = IP(src=dst, dst=src)/TCP(flags="SA", sport=dport, dport=sport, seq=s_isn, ack=syn.seq+1)
    ack = IP(src=src, dst=dst)/TCP(flags="A", sport=sport, dport=dport, seq=syn.seq+1, ack=synack.seq+1)
    pktdump.write(syn)
    pktdump.write(synack)
    pktdump.write(ack)
    return ack.seq, ack.ack

def build_finshake(src, dst, sport, dport, seq, ack):
    fin = IP(src=src, dst=dst)/TCP(flags="FA", sport=sport, dport=dport, seq=seq, ack=ack)
    final_ack = IP(src=dst, dst=src)/TCP(flags="A", sport=dport, dport=sport, seq=ack, ack=seq+1)
    pktdump.write(fin)
    pktdump.write(final_ack)

def chunkstring(s, n):
    return (s[i:i+n] for i in range(0, len(s), n))

def make_poop(src, dst, sport, dport, seq, ack, payload):
    # Ensure payload is bytes
    if isinstance(payload, str):
        payload = payload.encode()
    segments = list(chunkstring(payload, 1460)) if len(payload) > 1460 else [payload]
    for seg in segments:
        p = IP(src=src, dst=dst)/TCP(flags="PA", sport=sport, dport=dport, seq=seq, ack=ack)/Raw(load=seg)
        ra = IP(src=dst, dst=src)/TCP(flags="A", sport=dport, dport=sport, seq=p.ack, ack=p.seq + len(seg))
        seq = ra.ack
        ack = ra.seq
        pktdump.write(p)
        pktdump.write(ra)
    return seq, ack

# Handle .saz archive
if options.input_is_saz and os.path.isfile(options.input_target):
    try:
        options.tmpdir = tempfile.mkdtemp()
        with zipfile.ZipFile(options.input_target, "r") as z:
            z.extractall(options.tmpdir)
    except:
        print("Failed to open or extract SAZ file")
        sys.exit(-1)
    raw_dir = os.path.join(options.tmpdir, "raw")
    if os.path.isdir(raw_dir):
        options.fiddler_raw_dir = raw_dir + "/"
    else:
        print("Failed to locate raw directory inside SAZ")
        sys.exit(-1)
elif os.path.isdir(options.input_target):
    options.fiddler_raw_dir = options.input_target
    options.tmpdir = None
else:
    print("Invalid input target")
    sys.exit(-1)

# Main parsing loop
if os.path.isdir(options.fiddler_raw_dir):
    mlist = glob.glob(os.path.join(options.fiddler_raw_dir, "*_m.xml"))
    mlist.sort()
    for xml_file in mlist:
        sport = ""
        dport = 80
        dom = parse(xml_file)
        fid = re.match(r"^(\d+)_m\.xml", os.path.basename(xml_file)).group(1)

        # Pull IPs and port from session flags
        xmlTags = dom.getElementsByTagName('SessionFlag')
        for tag in xmlTags:
            txt = tag.toxml()
            m = re.match(r'<SessionFlag N="x-(?:client(?:ip" V="[^"]*?(?P<clientip>\d{1,3}(?:\.\d{1,3}){3})|port" V="(?P<sport>\d+))|hostip" V="[^"]*?(?P<hostip>\d{1,3}(?:\.\d{1,3}){3}))"', txt)
            if m and m.group("sport"):
                sport = int(m.group("sport"))
            elif m and m.group("clientip") and src is None:
                src = m.group("clientip")
            elif m and m.group("hostip") and dst is None:
                dst = m.group("hostip")

        # Read client request (raw bytes)
        with open(os.path.join(options.fiddler_raw_dir, f"{fid}_c.txt"), "rb") as f:
            req = f.read()

        # Un-proxy URL if needed
        try:
            first_line = req.decode("utf-8", errors="ignore").splitlines()[0]
            m2 = re.match(r"^[^\s]+\s+(?P<host>https?://[^/\s:]+(:\d{1,5})?)\/", first_line)
            if m2 and options.dproxy and m2.group("host"):
                req = req.replace(m2.group("host").encode(), b"", 1)
                if m2.group(2):
                    port_candidate = int(m2.group(2).lstrip(":"))
                    if port_candidate <= 65535:
                        dport = port_candidate
        except:
            pass

        # Read server response
        with open(os.path.join(options.fiddler_raw_dir, f"{fid}_s.txt"), "rb") as f:
            resp = f.read()

        print(f"src: {src} dst: {dst} sport: {sport} dport: {dport}")
        (seq, ack) = build_handshake(src, dst, sport, dport)
        (seq, ack) = make_poop(src, dst, sport, dport, seq, ack, req)
        (seq, ack) = make_poop(dst, src, dport, sport, seq, ack, resp)
        build_finshake(src, dst, sport, dport, seq, ack)

    if options.tmpdir:
        try:
            shutil.rmtree(options.tmpdir)
        except:
            print(f"Could not remove temp directory {options.tmpdir}")

pktdump.close()
