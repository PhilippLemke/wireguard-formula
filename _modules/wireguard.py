"""
Wireguard basic module
"""
from subprocess import Popen, PIPE

#       try:
#            mail_process = subprocess.Popen(
#                ["mail", "-s", subject, "-c", cc, email], stdin=subprocess.PIPE
#            )
#        except Exception as e:  # pylint: disable=broad-except
#            log.error("unable to send email to %s: %s", email, e)
#
#        mail_process.communicate(message)


##                    try:
##                        stdout = subprocess.Popen(
##                            [
##                                "qemu-img",
##                                "info",
##                                "-U",
##                                "--output",
##                                "json",
##                                "--backing-chain",
##                                qemu_target,
##                            ],
##                            shell=False,
##                            stdout=subprocess.PIPE,
##                        ).communicate()[0]
##



def create_peer_config(pillar_file=False, qrcode=False):
    #force = __pillar__.get("zypper", {}).get("refreshdb_force", True)
    #wg_pillar = __pillar__.get("wireguard", {}).get("interfaces",{})
    peer_cfg = {}
    for interface, config in __pillar__.get("wireguard", {}).get("interfaces",{}).items():
        if "easy_peer" in config:
            for peer in config["easy_peer"]['peers']:
              genkey= Popen(["wg", "genkey"], shell=False, stdout=PIPE).communicate()[0]
              pubkey= Popen(["wg", "pubkey"], shell=False, stdin=PIPE, stdout=PIPE).communicate(input=genkey)[0]
              peer_cfg.update({ peer : {'PrivateKey' : genkey, 'PublicKey' : pubkey }})
            
    ret = peer_cfg  
    return ret
