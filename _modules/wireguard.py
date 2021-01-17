"""
Wireguard basic module
"""
from subprocess import Popen, PIPE
from ipaddress import ip_network
from os import path
import re

def _write_classic_config(peer_conf_dir, peer_cfg, qrcode, qrcode_type):
    ret = {'peers' : {} }
            
    if path.isdir(peer_conf_dir):
        for interface, peers in peer_cfg.items():
            for peer, pdata in peers.items():
                cfg_file = '{}/{}_{}.conf'.format(peer_conf_dir, interface, peer)
                f = open(cfg_file, 'w')
                f.write('[Interface]\n')
                f.write('PrivateKey = {}\n'.format(pdata['PrivateKey']))
                f.write('Address = {}\n'.format(pdata['Address']))
                f.write('DNS = {}\n'.format(pdata['DNS']))
                f.write('[Peer]\n')
                f.write('PublicKey = {}\n'.format(pdata['PublicKey']))
                f.write('Endpoint = {}\n'.format(pdata['Endpoint']))
                f.close()
                ret['peers'].update({peer : { 'cfg_file' : cfg_file }})
                if qrcode:
                    qrcode = Popen(['qrencode', '-t', qrcode_type], shell=False, stdin=PIPE, stdout=PIPE).communicate(input=open('{}/{}_{}.conf'.format(peer_conf_dir, interface, peer), 'r').read() )[0]
                    if qrcode_type == 'ansiutf8':
                        # https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python/14693789#14693789
                        # Definitely the more efficent way compared with my own regex before...
                        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                        qrcode = ansi_escape.sub('', qrcode)
                    ret['peers'][peer].update({ 'qrcode' : str(qrcode)})
                    #open(cfg_file + 'qrcode', 'w').write())
        return ret
    else:
        return False


def create_peer_config(pillar_files=False, pillar_dir='/srv/pillar/wireguard', write_peer_conf=False, peer_conf_dir='/etc/wireguard/client-config', qrcode=False, qrcode_type='ansiutf8'):
    peer_cfg = {}
    for interface, config in __pillar__.get('wireguard', {}).get('interfaces',{}).items():
        peer_cfg[interface] = {}
        hosts_in_net = [ str(h) for h in ip_network(u'%s' %config['config']['Address'], strict=False).hosts() ]
        #ignore first IP
        avail_peer_ips = hosts_in_net[1:]

        if 'easy_peer' in config:
            for idx, peer in enumerate(sorted(config['easy_peer']['peers'])):
            #for peer in config["easy_peer"]['peers']:
              genkey= Popen(['wg', 'genkey'], shell=False, stdout=PIPE).communicate()[0]
              pubkey= Popen(['wg', 'pubkey'], shell=False, stdin=PIPE, stdout=PIPE).communicate(input=genkey)[0]
              peer_cfg[interface].update({ peer : {'PrivateKey' : genkey.strip(),
                                        'PublicKey' : pubkey.strip(),
                                        'Address' : avail_peer_ips[idx],
                                        'DNS' : config['easy_peer']['DNS'],
                                        'Endpoint' : config['easy_peer']['Endpoint'],
                                        }})
    if write_peer_conf:
        ret = _write_classic_config(peer_conf_dir, peer_cfg, qrcode, qrcode_type)

    return ret
