"""
Wireguard basic module
"""
import logging
from subprocess import Popen, PIPE
from ipaddress import ip_network
from os import path
import re
import yaml

def _write_classic_config(peer_conf_dir, peer_cfg, qrcode, qrcode_type):
    ret = {'peers' : {} }
    if path.isdir(peer_conf_dir):
        for interface in peer_cfg:
            for peer, peer_cfg in peer_cfg[interface].items():
                cfg_file = '{}/{}_{}.conf'.format(peer_conf_dir, interface, peer)
                f = open(cfg_file, 'w')
                for section, params in peer_cfg.items():
                    f.write('[{}]\n'.format(section))
                    for k, v in params.items():
                        if type(v) == list:
                            v = ", ".join(v)
                        f.write('{} = {}\n'.format(k, v))
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
        return ret
    else:
        return False

def wg_genkey():
    '''
    Generates a Wireguard private and public key
    Return tuple
    '''
    genkey = Popen(['wg', 'genkey'], shell=False, stdout=PIPE).communicate()[0]
    pubkey = Popen(['wg', 'pubkey'], shell=False, stdin=PIPE, stdout=PIPE).communicate(input=genkey)[0]
    key = { 'pub' : pubkey.strip(), 'priv' : genkey.strip() }
    return key

def create_peer_config(pillar_files=False, pillar_dir='/srv/pillar/wireguard', write_pillar_peer_conf=False, write_classic_peer_conf=False, peer_conf_dir='/etc/wireguard/client-config', qrcode=False, qrcode_type='ansiutf8'):
    #wg_pillar = __pillar__.get('wireguard', {}).get('interfaces',{})
    #wg_pillar =  { 'wireguard' : { 'interfaces' {} }}
    wg_pillar = {}
    peer_cfg = {}
    for interface, config in __pillar__.get('wireguard', {}).get('interfaces',{}).items():
        peer_cfg[interface] = {}
        peer_cfg[interface] = config['easy_peer']['peers']
        hosts_in_net = [ str(h) for h in ip_network(u'%s' %config['config']['Address'], strict=False).hosts() ]
        #ignore first IP
        avail_peer_ips = hosts_in_net[1:]

        if 'easy_peer' in config:
            # Generate server private and public key
            server_key = wg_genkey()
            wg_pillar[interface] = { 'config' : {'PrivateKey' : server_key['priv'] }, 'peers' : []}

            for idx, peer in enumerate(sorted(config['easy_peer']['peers'])):
                # Generate client private and public key
                client_key = wg_genkey()
                # define globals for each peer
                peer_cfg[interface][peer] = config['easy_peer']['globals']
                
                # define custom peer cfg and overwrite globals if defined            
                peer_cfg[interface][peer]['Interface'].update({'PrivateKey' : client_key['priv'], 'Address' : avail_peer_ips[idx] })
                peer_cfg[interface][peer]['Peer'].update({ 'PublicKey' : server_key['pub'] })
                # Update server client config part
                wg_pillar[interface]['peers'].append({ 'PublicKey' :  client_key['pub'], 'AllowedIPs' : [avail_peer_ips[idx]] })

    if write_classic_peer_conf:
        ret = _write_classic_config(peer_conf_dir, peer_cfg, qrcode, qrcode_type)

    if write_pillar_peer_conf:
        wg_pillar = { 'wireguard' : { 'interfaces' : wg_pillar } }
        with open(pillar_dir + '/easy_peer.sls', 'w') as pillar_file:
            yaml.dump(wg_pillar, pillar_file, default_flow_style=False)

    return ret
