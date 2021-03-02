"""
Wireguard basic module
"""
import logging
from subprocess import Popen, PIPE
from ipaddress import ip_network
from os import path
from os import listdir
import os
import re
import yaml
from copy import deepcopy

def _write_conf(cfg_file, peer_cfg):
    f = open(cfg_file, 'w')
    for section, params in peer_cfg.items():
        f.write('[{}]\n'.format(section))
        for k, v in params.items():
            if type(v) == list:
                v = ", ".join(v)
            f.write('{} = {}\n'.format(k, v))
    f.close()


def _gen_filenames(peer_conf_dir, interface, peer):
    peer_file_path = '{}/{}_{}'.format(peer_conf_dir, interface, peer)
    #return a tuple yml, conf file
    return  ( '{}.yml'.format(peer_file_path), '{}.conf'.format(peer_file_path) )
    

def _write_classic_config(peer_conf_dir, peer_cfg, qrcode, qrcode_type):
    ret = {'peers' : {} }
    if path.isdir(peer_conf_dir):
        for interface in peer_cfg:
            for peer, peer_cfg in peer_cfg[interface].items():
                yml_file, cfg_file  = _gen_filenames(peer_conf_dir, interface, peer)

                #write conf file
                _write_conf(cfg_file, peer_cfg)
                ret['peers'].update({peer : { 'cfg_file' : cfg_file }})

                # write conf also as yml
                open(yml_file, 'w').write(yaml.dump(peer_cfg, default_flow_style=False))

                if qrcode:
                    qrcode = Popen(['qrencode', '-t', qrcode_type], shell=False, stdin=PIPE, stdout=PIPE).communicate(input=open('{}/{}_{}.conf'.format(peer_conf_dir, interface, peer), 'r').read() )[0]
                    if qrcode_type == 'ansiutf8':
                        # https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python/14693789#14693789
                        # Definitely the more efficient way compared with my own regex before...
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

def _read_yml_conf(peer_conf_dir, interface):
    existing_peer_cfg = {}
    for cfg_file in listdir(peer_conf_dir):
        if cfg_file.startswith(interface) and cfg_file.endswith('.yml'):
            peer = cfg_file.lstrip(interface + '_').rstrip('.yml')
            full_cfg_path = '{}/{}'.format(peer_conf_dir,cfg_file)
            existing_peer_cfg.update({ peer : yaml.load(open(full_cfg_path, 'r').read()) })
    return existing_peer_cfg


def create_peer_config(pillar_files=False, pillar_dir='/srv/pillar/wireguard', write_pillar_peer_conf=False, write_classic_peer_conf=False, peer_conf_dir='/etc/wireguard/easy_peer', qrcode=False, qrcode_type='ansiutf8', del_unmanaged_peers=False):
    wg_pillar = {}
    peer_cfg = {}
    # Iterate over existing wireguard pillars
    for interface, config in __pillar__.get('wireguard', {}).get('interfaces',{}).items():
        #peer_cfg[interface] = {}

        # Use ip_network module to create a list of all ip addresses of the given network
        # Based on the server config value address (e.g. 10.10.10.1/24)
        hosts_in_net = [ str(h) for h in ip_network(u'{}'.format(config['config']['Address']), strict=False).hosts() ]
        # Ignore first IP 
        avail_peer_ips = hosts_in_net[1:]

        if 'easy_peer' in config:
            # Read existing config into a dict 
            existing_peer_cfg = _read_yml_conf(peer_conf_dir, interface)
            import pprint
            #logging.warning(pprint.pformat(config))
            #logging.warning(pprint.pformat(existing_peer_cfg))

            if 'PrivateKey' in config['config']:
                server_key = {}
                logging.warning("Private server key already defined in pillar")
                wg_pillar[interface] = { 'config' : {'PrivateKey' : config['config']['PrivateKey'] }, 'peers' : []}
                # Try to fetch Server pub key from existing peer configuration
                try:
                    if len(existing_peer_cfg) == 0:
                        raise
                    for peer, data in existing_peer_cfg.items():
                        if 'PublicKey' in data['Peer']:
                            server_key['pub'] = data['Peer']['PublicKey']
                            logging.warning("Public server key used from existing peer configuration")
                            break
                except:
                    logging.error("Unable to detect existing server pub key from peer configuration, please remove easy_peer pillar")
                    import sys
                    sys.exit(2)

            else:
                logging.warning("Generate and set new server private key")
                # Generate server private and public key
                server_key = wg_genkey()
                wg_pillar[interface] = { 'config' : {'PrivateKey' : server_key['priv'] }, 'peers' : []}
            
            peer_cfg[interface] = {}
            for idx, peer in enumerate(sorted(config['easy_peer']['peers'])):
                # Generate client private and public key
                client_key = wg_genkey()
                
                # Define globals which will be effective for each peer configuration.
                # Source: Standard wireguard pillar interface -> easy_peer -> globals 
                peer_cfg[interface][peer] = deepcopy(config['easy_peer']['globals'])

                if peer in existing_peer_cfg:
                    logging.warning('Peer config for: {} already exists!'.format(peer))
                    # Add peer config from existing_peer_cfg to peer_cfg
                    peer_cfg[interface][peer]['Interface'].update({'PrivateKey' : existing_peer_cfg[peer]['Interface']['PrivateKey'] , 'Address' : avail_peer_ips[idx] })
                    peer_cfg[interface][peer]['Peer'].update({ 'PublicKey' : existing_peer_cfg[peer]['Peer']['PublicKey'] })
                     
                    # Iterate over already defined easy_peer pillar structure
                    for ex_peer in config['peers']:
                        for ip in ex_peer['AllowedIPs']:
                            if ip == avail_peer_ips[idx]:
                                # Update easy_peer pillar with already used pubkey and IP, to keep client functionality  
                                wg_pillar[interface]['peers'].append({ 'PublicKey' :  ex_peer['PublicKey'], 'AllowedIPs' : [ip] })
                        
                else:
                    # Update server client config part
                    wg_pillar[interface]['peers'].append({ 'PublicKey' :  client_key['pub'], 'AllowedIPs' : [avail_peer_ips[idx]] })

                    peer_cfg[interface][peer]['Interface'].update({'PrivateKey' : client_key['priv'], 'Address' : avail_peer_ips[idx] })
                    peer_cfg[interface][peer]['Peer'].update({ 'PublicKey' : server_key['pub'] })
                
                # Update Interface
                try:
                    # Try to update config with client specific interface params
                    peer_cfg[interface][peer]['Interface'].update(config['easy_peer']['peers'][peer]['Interface'])
                except:
                    # No client specific params defined
                    pass

                # Update peer
                try:
                    # Try to update config with client specific peer params
                    peer_cfg[interface][peer]['Peer'].update(config['easy_peer']['peers'][peer]['Peer'])
                except:
                    # No client specific params defined
                    pass

    if write_classic_peer_conf:
        ret = _write_classic_config(peer_conf_dir, peer_cfg, qrcode, qrcode_type)

    if write_pillar_peer_conf:
        wg_pillar = { 'wireguard' : { 'interfaces' : wg_pillar } }
        with open(pillar_dir + '/easy_peer.sls', 'w') as pillar_file:
            yaml.dump(wg_pillar, pillar_file, default_flow_style=False)

    if del_unmanaged_peers:
        file_ext = ["yml", "conf"]
        logging.warning("delete unmanaged peers")
        # Update existing config dict to ensure that config from the current run is honored 
        existing_peer_cfg = _read_yml_conf(peer_conf_dir, interface)

        # Check for an delta between existing configuration and configured peers in pillars
        all(map(existing_peer_cfg.pop, config["easy_peer"]["peers"]))
        if len(existing_peer_cfg) > 0:
            for peer in existing_peer_cfg:
                for ext in file_ext:
                    cfgfile = "{dir}/{inf}_{peer}.{ext}".format(dir=peer_conf_dir, inf=interface, peer=peer, ext=ext)
                    logging.warning("rm {}".format(cfgfile))
                    os.unlink(cfgfile)

    return ret
