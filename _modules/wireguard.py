"""
Wireguard basic module
"""
from subprocess import Popen, PIPE
from ipaddress import ip_network

def create_peer_config(pillar_files=False, pillar_dir='/srv/pillar/wireguard', qrcode=False):
    peer_cfg = {}
    for interface, config in __pillar__.get("wireguard", {}).get("interfaces",{}).items():
        hosts_in_net = [ str(h) for h in ip_network(u'%s' %config['config']['Address'], strict=False).hosts() ]
        #ignore first IP
        avail_peer_ips = hosts_in_net[1:]

        if "easy_peer" in config:
            for idx, peer in enumerate(sorted(config["easy_peer"]['peers'])):
            #for peer in config["easy_peer"]['peers']:
              genkey= Popen(["wg", "genkey"], shell=False, stdout=PIPE).communicate()[0]
              pubkey= Popen(["wg", "pubkey"], shell=False, stdin=PIPE, stdout=PIPE).communicate(input=genkey)[0]
              peer_cfg.update({ peer : {'PrivateKey' : genkey,
                                        'PublicKey' : pubkey,
                                        'Address' : avail_peer_ips[idx],
                                        }})
    ret = peer_cfg
    #ret = pprint(avail_peer_ips)
    return ret
