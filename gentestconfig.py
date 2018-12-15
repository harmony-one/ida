import argparse
import hashlib
import io
import json
import logging
import os
import os.path
import shlex
import subprocess
import sys

sq = shlex.quote
logger = logging.getLogger(__name__)


DEFAULT_NAME_TAG = 'IDA Test Instance'
#DEFAULT_NAME_TAG = 'IDA_test'
DEFAULT_SSH_KEY = os.path.join(os.environ['HOME'], '.ssh', 'ida')
#DEFAULT_SSH_KEY = os.path.join(os.environ['HOME'], '.ssh', 'ida.pem')
DEFAULT_IDA_DIR = 'go/src/github.com/harmony-one/ida'



def _main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile',
                        help="""profile section in ~/.aws/credentials""")
    parser.add_argument('--name', dest='name_tag',
                        help=f"""instance name tag to match
                                 (default: {DEFAULT_NAME_TAG})""")
    parser.add_argument('--ssh-key', metavar='FILE',
                        help=f"""SSH key file to use
                                 (default: {DEFAULT_SSH_KEY})""")
    parser.add_argument('--ssh-user', metavar='FILE',
                        help=f"""remote SSH username (default: ubuntu)""")
    parser.add_argument('--ida-dir', metavar='FILE',
                        help=f"""harmony-one/ida repository path on instance
                                 (default: {DEFAULT_IDA_DIR})""")
    parser.add_argument('--action', metavar='ACTION', dest='actions',
                        help=f"""action(s) to take, a comma-separated list of:
                                 gen, start, stop, send, update""")
    parser.add_argument('--file', metavar='FILE',
                        help=f"""the file to send (for --action=send)""")
    parser.add_argument('num_instances', type=int, metavar='N',
                        help="""number of instances""")
    parser.add_argument('regions', nargs='+', metavar='REGION',
                        help="""AWS regions (such as us-west-2)""")
    parser.set_defaults(name_tag=DEFAULT_NAME_TAG,
                        profile='default',
                        ssh_key=DEFAULT_SSH_KEY,
                        ssh_user='ubuntu',
                        ida_dir=DEFAULT_IDA_DIR,
                        actions='send')
    args = parser.parse_args()

    logger.info(f"collecting all IP addresses")

    ips = {}
    all_ips = []

    for region in args.regions:
        proc = subprocess.run(['aws', f'--profile={args.profile}',
                               f'--region={region}',
                               'ec2', 'describe-instances',
                               f'--filters=Name=tag:Name,'
                               f'Values={args.name_tag!r}'],
                              stdout=subprocess.PIPE, check=True)
        r = json.loads(proc.stdout)
        ips1 = []
        for reservation in r['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] == 'running':
                    ips1.append(instance['PublicIpAddress'])
        ips1.sort(key=lambda ip: tuple(int(b) for b in ip.split('.')))
        if len(ips1) != args.num_instances:
            raise RuntimeError(f"{region} has {len(ips1)} matching instances,"
                               f" not {args.num_instances}")
        ips[region] = ips1
        all_ips.extend(ips1)

    ida_dir = sq(args.ida_dir)

    def ssh(ip, cmd, **kwargs):
        return subprocess.run(['ssh',
                               '-oStrictHostKeyChecking=no',
                               '-oUserKnownHostsFile=/dev/null',
                               '-oControlMaster=auto',
                               '-oControlPersist=yes',
                               f'-i{sq(args.ssh_key)}',
                               f'{args.ssh_user}@{ip}', cmd],
                              **kwargs)

    for action in args.actions.split(','):
        action = action.strip()
        if action == 'gen':
            logger.info(f"generating configurations")

            all_peers_config = io.StringIO()
            peer_configs = [io.StringIO() for ip in all_ips]
            for idx, ip in enumerate(all_ips):
                pk = hashlib.sha1(ip.encode()).hexdigest()
                print(f"{idx} {ip} 20000 10000 {pk} 2", file=all_peers_config)
                with open(f'configs/{idx}.txt', 'w') as peer_config:
                    print(f"{idx} {ip} 20000 10000 {pk} 0", file=peer_configs[idx])
                    for idx2, ip2 in enumerate(all_ips):
                        if idx2 == idx:
                            continue
                        pk2 = hashlib.sha1(ip2.encode()).hexdigest()
                        print(f"{idx2} {ip2} 20000 10000 {pk2} 1",
                              file=peer_configs[idx])
            all_peers_config = all_peers_config.getvalue().encode()
            for idx, peer_config in enumerate(peer_configs):
                peer_configs[idx] = peer_config.getvalue().encode()

            logger.info(f"copying all-peer configs")
            for idx, ip in enumerate(all_ips):
                logger.info(f"... {ip}")
                ssh(ip, f'cat > {ida_dir}/configs/all_peers.txt',
                    input=all_peers_config, check=True)

            logger.info(f"copying per-peer configs")
            for idx, ip in enumerate(all_ips):
                logger.info(f"... {ip}")
                ssh(ip, f'cat > {ida_dir}/configs/config.txt',
                    input=peer_configs[idx], check=True)

        elif action == 'start':
            logger.info(f"starting server")
            for idx, ip in enumerate(all_ips):
                logger.info(f"... {ip}")
                if idx == 0:
                    continue
                ssh(ip,
                    f'cd {ida_dir} && ls -l ida && {{ ./ida '
                    '-nbr_config configs/config.txt '
                    '-all_config configs/all_peers.txt '
                    '> ida.out 2>&1 & ls -l ida.out || :; }',
                    check=True)

        elif action == 'stop':
            logger.info(f"stopping server")
            for idx, ip in enumerate(all_ips):
                logger.info(f"... {ip}")
                ssh(ip, f'killall ida')

        elif action == 'send':
            if args.file is None:
                parser.error("--file not specified")
            logger.info(f"sending one file: {args.file}")
            with open(args.file, 'rb') as f:
                contents = f.read()
            hex_hash = hashlib.sha1(contents).hexdigest()
            logger.info(f"{len(contents)} byte(s), sha1 {hex_hash}")
            logger.info(f"copying over")
            ssh(all_ips[0], f'cat > {ida_dir}/{hex_hash}.dat',
                    input=contents, check=True)
            logger.info(f"invoking ida")
            ssh(all_ips[0],
                f'cd {ida_dir} && ./ida '
                f'-nbr_config configs/config.txt '
                f'-all_config configs/all_peers.txt '
                f'-broadcast -msg_file {hex_hash}.dat '
                f'-t0 5 '
                f'-t1 50 '
                f'-base 1.01 '
                f'2>&1 | tee ida.out',
                check=True)

        elif action == 'update':
            logger.info(f"downloading new binary from s3")
            url = 'https://s3.us-east-2.amazonaws.com/harmony-ida-binary/ida'
            for ip in all_ips:
                logger.info(f"... {ip}")
                ssh(ip,
                    f'cd {ida_dir} && '
                    f'rm -f ida && '
                    f'curl -LsS -o ida {url} && '
                    f'chmod a+x ida')


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    try:
        _main()
    except RuntimeError as e:
        logger.critical(str(e))
        sys.exit(1)
