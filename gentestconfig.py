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
from pssh.clients import ParallelSSHClient
from gevent import joinall

sq = shlex.quote
logger = logging.getLogger(__name__)


DEFAULT_NAME_TAG = 'IDA Test Instance'
DEFAULT_SSH_KEY = os.path.join(os.environ['HOME'], '.ssh', 'ida')
DEFAULT_IDA_DIR = 'go/src/github.com/harmony-one/ida'
DEFAULT_T0 = 5
DEFAULT_T1 = 50
DEFAULT_EXP_BASE = 1.05


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
    parser.add_argument('--id', metavar='NODE_ID_IN_REGION',type=int,
                        help=f"""the node is in a given region to login""")
    parser.add_argument('--query', metavar='search query',
                        help=f"""search given query from the nodes """)
    parser.add_argument('--t0', type=int, metavar='MILLISECONDS',
                        help=f"""minimum interpacket delay
                                 (default: {DEFAULT_T0})""")
    parser.add_argument('--t1', type=int, metavar='MILLISECONDS',
                        help=f"""maximum interpacket delay
                                 (default: {DEFAULT_T1})""")
    parser.add_argument('--exp-base', type=float, metavar='NUM',
                        help=f"""interpacket delay exponential base
                                 (default: {DEFAULT_EXP_BASE})""")
    parser.add_argument('num_instances', type=int, metavar='N',
                        help="""number of instances""")
    parser.add_argument('regions', nargs='+', metavar='REGION',
                        help="""AWS regions (such as us-west-2)""")
    parser.set_defaults(name_tag=DEFAULT_NAME_TAG,
                        profile='default',
                        ssh_key=DEFAULT_SSH_KEY,
                        ssh_user='ubuntu',
                        ida_dir=DEFAULT_IDA_DIR,
                        actions='send',
                        t0=DEFAULT_T0,
                        t1=DEFAULT_T1,
                        exp_base=DEFAULT_EXP_BASE)
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
        if len(ips1) < args.num_instances:
            raise RuntimeError(f"{region} has {len(ips1)} matching instances,"
                               f"should be greater or equal than {args.num_instances}")
        logger.info(f"total {len(ips1)} running instances in {region}")
        ips1 = ips1[:args.num_instances]
        ips[region] = ips1
        print(f"in {region} will use {len(ips[region])} instances")
        all_ips.extend(ips1)

    ida_dir = sq(args.ida_dir)

    def ssh(host_list, cmd, **kargs):
        try:
            client = ParallelSSHClient(host_list,user='ubuntu',pkey=f'{sq(args.ssh_key)}')
            output = client.run_command(cmd,**kargs)
            for host in output:
                logger.info(host)
                for line in output[host]['stdout']:
                    logger.info(line)
        except:
            logger.info('cannot connect to all the hosts')
            return

    def ssh1(ip, cmd, **kwargs):
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
        if action == 'login':
            logger.info(f"log into given remote host")
            ip = ips[region][args.id]
            subprocess.run(['ssh',f'-i{sq(args.ssh_key)}',
                           f'{args.ssh_user}@{ip}'])
        if action == 'gen':
            logger.info(f"generating configurations")

            all_peers_config = io.StringIO()
            peer_configs = [io.StringIO() for ip in all_ips]
            for idx, ip in enumerate(all_ips):
                pk = hashlib.sha1(ip.encode()).hexdigest()
                print(f"{idx} {ip} 20000 10000 {pk} 2", file=all_peers_config)
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

            logger.info(f"removing old config files")
            ssh(all_ips, f'rm -f {ida_dir}/configs/*')

            with open('all_peers.txt','wb') as f:
                f.write(all_peers_config)
            logger.info(f"copying all-peer configs")
            client = ParallelSSHClient(all_ips,user='ubuntu',pkey=f'{sq(args.ssh_key)}')
            greenlets = client.copy_file('all_peers.txt', f'{ida_dir}/configs/all_peers.txt')
            joinall(greenlets, raise_error=True)

            logger.info(f"copying per-peer configs")
            for idx, ip in enumerate(all_ips):
                logger.info(f"... {ip}")
                ssh1(ip, f'cat > {ida_dir}/configs/config.txt',
                    input=peer_configs[idx], check=True)

        elif action == 'start':
            logger.info(f"starting server")
            logger.info(all_ips[1:])
            ssh(all_ips[1:],
                f'cd {ida_dir} && ls -l ida && {{ ./ida '
                '-nbr_config configs/config.txt '
                '-all_config configs/all_peers.txt '
                '> ida.out 2>&1 & ls -l ida.out || :; }')

        elif action == 'stop':
            logger.info(f"stopping server, and remove received files")
            ssh(all_ips, f'killall ida && rm -f {ida_dir}/received/*')

        elif action == 'send':
            if args.file is None:
                parser.error("--file not specified")
            logger.info(f"sending one file: {args.file}")
            with open(args.file, 'rb') as f:
                contents = f.read()
            hex_hash = hashlib.sha1(contents).hexdigest()
            logger.info(f"{len(contents)} byte(s), sha1 {hex_hash}")
            logger.info(f"copying over")
            ssh1(all_ips[0], f'cat > {ida_dir}/{hex_hash}.dat',
                    input=contents, check=True)
            logger.info(f"invoking ida")
            ssh1(all_ips[0],
                f'cd {ida_dir} && ./ida '
                f'-nbr_config configs/config.txt '
                f'-all_config configs/all_peers.txt '
                f'-broadcast -msg_file {hex_hash}.dat '
                f'-t0 {args.t0} '
                f'-t1 {args.t1} '
                f'-base {args.exp_base} '
                f'2>&1 | tee ida.out',
                check=True)

        elif action == 'grep':
            if args.query is None:
                parser.error("--query not specified")
            query = sq(args.query)
            logger.info(f"searching for {args.query} from nodes")
            logger.info("**********************************************************")
            ssh(all_ips,f'cd {ida_dir} && ls -l ida.out && '
                f'ag {query} ida.out | cat')

        elif action == 'update':
            logger.info(f"downloading new binary from s3")
            url = 'https://s3.us-east-2.amazonaws.com/harmony-ida-binary/ida'
            ssh(all_ips,
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
