from __future__ import annotations
import argparse, json, socket, sys
from pathlib import Path
from firebox import __version__
from firebox.core import emit, write_report
from firebox.modules import network, password_tools, log_analyzer, integrity, web_security, web_audit, web_enumeration, metadata, system, vulns, wifi, phishing, api_discovery

def ports_arg(value):
    try: ports=[int(x.strip()) for x in value.split(',')]; assert all(1<=p<=65535 for p in ports); return ports
    except Exception as exc: raise argparse.ArgumentTypeError("ports must be comma-separated integers 1-65535") from exc

def add_common(p): p.add_argument('--json', action='store_true'); p.add_argument('--report', help='write JSON report to this path')
def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    # Short aliases for the common operator workflow. The expanded commands
    # remain available for scripts and backwards compatibility.
    if argv:
        aliases = {
            'scan': ['network', 'scan'],
            'ports': ['network', 'ports'],
            'dns': ['dns', 'lookup'],
            'web': ['web', 'check'],
            'vuln-scan': ['web', 'audit'],
            'logs': ['logs', 'analyze'],
            'hash': ['hash', 'generate'],
            'metadata': ['metadata', 'inspect'],
        }
        if argv[0] == 'vuln-scan' and len(argv) >= 2 and argv[1].startswith('-'):
            argv = ['web', 'audit'] + argv[1:]
        elif argv[0] in aliases and len(argv) >= 2 and not argv[1].startswith('-'):
            command, value, rest = aliases[argv[0]], argv[1], argv[2:]
            option = '--domain' if argv[0] == 'dns' else '--url' if argv[0] in {'web', 'vuln-scan'} else '--file' if argv[0] in {'logs', 'hash', 'metadata'} else '--target'
            argv = command + [option, value] + rest
    parser=argparse.ArgumentParser(prog='firebox', description='Firebox Cyber Toolkit: authorized defensive security operations')
    parser.add_argument('--version', action='version', version=__version__); sub=parser.add_subparsers(dest='module', required=True)
    net=sub.add_parser('network'); ns=net.add_subparsers(dest='action', required=True); scan=ns.add_parser('scan'); scan.add_argument('--target',required=True); scan.add_argument('--ports',type=ports_arg,default=list(range(1,1025))); scan.add_argument('--timeout',type=float,default=2); scan.add_argument('--workers',type=int,default=8); add_common(scan); pp=ns.add_parser('ports'); pp.add_argument('--target',required=True); pp.add_argument('--ports',type=ports_arg,required=True); pp.add_argument('--timeout',type=float,default=2); add_common(pp)
    dns=sub.add_parser('dns'); d=dns.add_subparsers(dest='action',required=True); dl=d.add_parser('lookup'); dl.add_argument('--domain',required=True); add_common(dl)
    web=sub.add_parser('web'); wc=web.add_subparsers(dest='action',required=True); w=wc.add_parser('check'); w.add_argument('--url',required=True); w.add_argument('--timeout',type=float,default=8); add_common(w); audit=wc.add_parser('audit'); audit.add_argument('--url',required=True); audit.add_argument('--paths',help='comma-separated explicit paths, maximum 8'); audit.add_argument('--timeout',type=float,default=8); add_common(audit); enum=wc.add_parser('enumerate'); enum.add_argument('--url',required=True); enum.add_argument('--wordlist',required=True); enum.add_argument('--max-requests',type=int,default=100); enum.add_argument('--delay',type=float,default=0.5); enum.add_argument('--timeout',type=float,default=5); enum.add_argument('--confirm-authorized',action='store_true'); add_common(enum)
    logs=sub.add_parser('logs'); la=logs.add_subparsers(dest='action',required=True); l=la.add_parser('analyze'); l.add_argument('--file',required=True); l.add_argument('--threshold',type=int,default=5); add_common(l)
    pw=sub.add_parser('password'); pws=pw.add_subparsers(dest='action',required=True); pg=pws.add_parser('generate'); pg.add_argument('--length',type=int,default=20); pgs=pws.add_parser('strength'); pgs.add_argument('--password',required=True); pgt=pws.add_parser('token'); pgt.add_argument('--length',type=int,default=32); add_common(pg); add_common(pgs); add_common(pgt)
    hs=sub.add_parser('hash'); h=hs.add_subparsers(dest='action',required=True); hg=h.add_parser('generate'); hg.add_argument('--file',required=True); hv=h.add_parser('verify'); hv.add_argument('--file',required=True); hv.add_argument('--expected',required=True); add_common(hg); add_common(hv)
    inte=sub.add_parser('integrity'); ic=inte.add_subparsers(dest='action',required=True); b=ic.add_parser('baseline'); b.add_argument('--path',required=True); b.add_argument('--baseline',default='data/firebox-baseline.json'); b.add_argument('--force',action='store_true'); add_common(b); s=ic.add_parser('scan'); s.add_argument('--path',required=True); s.add_argument('--baseline',default='data/firebox-baseline.json'); add_common(s)
    md=sub.add_parser('metadata'); mc=md.add_subparsers(dest='action',required=True); mi=mc.add_parser('inspect'); mi.add_argument('--file',required=True); add_common(mi)
    sy=sub.add_parser('system'); si=sy.add_subparsers(dest='action',required=True); inf=si.add_parser('info'); add_common(inf)
    wf=sub.add_parser('wifi', description='Read-only local wireless diagnostics; no nearby-network scanning or attack actions'); wfc=wf.add_subparsers(dest='action',required=True); wfs=wfc.add_parser('status'); add_common(wfs); wfa=wfc.add_parser('audit'); wfa.add_argument('--interface',required=True); add_common(wfa); wfp=wfc.add_parser('pcap'); wfp.add_argument('--file',required=True); add_common(wfp)
    ph=sub.add_parser('phishing', description='Defensive phishing analysis and synthetic awareness material only'); phc=ph.add_subparsers(dest='action',required=True); pha=phc.add_parser('analyze'); pha.add_argument('--file',required=True); add_common(pha); pht=phc.add_parser('template'); pht.add_argument('--scenario',required=True, choices=['suspicious-invoice','account-alert','delivery-notice']); pht.add_argument('--output');
    api=sub.add_parser('api', description='Read-only bounded API documentation discovery'); apic=api.add_subparsers(dest='action',required=True); apid=apic.add_parser('discover'); apid.add_argument('--url',required=True); apid.add_argument('--paths',help='comma-separated explicit documentation paths, maximum 8'); apid.add_argument('--timeout',type=float,default=5); add_common(apid)
    vu=sub.add_parser('vulns'); vc=vu.add_subparsers(dest='action',required=True); vl=vc.add_parser('list'); vl.add_argument('--db',default='data/firebox.db'); vl.add_argument('--status'); add_common(vl); va=vc.add_parser('add'); va.add_argument('--db',default='data/firebox.db'); va.add_argument('--title',required=True); va.add_argument('--severity',required=True); va.add_argument('--asset',required=True); va.add_argument('--evidence',required=True); va.add_argument('--remediation',required=True); va.add_argument('--status',default='open'); add_common(va)
    a=parser.parse_args(argv)
    try:
        if a.module=='network' and a.action=='scan': result=network.scan(a.target,a.ports,a.timeout,a.workers)
        elif a.module=='network': result=network.scan(a.target,a.ports,a.timeout,1)
        elif a.module=='dns': result=network.resolve(a.domain)
        elif a.module=='web' and a.action=='check': result=web_security.check(a.url,a.timeout)
        elif a.module=='web' and a.action=='audit': result=web_audit.audit(a.url,a.paths,a.timeout)
        elif a.module=='web': result=web_enumeration.enumerate_paths(a.url,a.wordlist,a.max_requests,a.delay,a.confirm_authorized,a.timeout)
        elif a.module=='logs': result=log_analyzer.analyze(a.file,a.threshold)
        elif a.module=='password' and a.action=='generate': print(password_tools.generate_password(a.length)); return 0
        elif a.module=='password' and a.action=='strength': result=password_tools.strength(a.password)
        elif a.module=='password': print(password_tools.generate_token(a.length)); return 0
        elif a.module=='hash':
            actual=password_tools.sha256_file(a.file); result={'file':a.file,'sha256':actual} if a.action=='generate' else {'file':a.file,'expected':a.expected,'actual':actual,'match':actual.lower()==a.expected.lower()}
        elif a.module=='integrity' and a.action=='baseline': result=integrity.create_baseline(a.path,a.baseline,a.force)
        elif a.module=='integrity': result=integrity.compare(a.path,a.baseline)
        elif a.module=='metadata': result=metadata.inspect(a.file)
        elif a.module=='system': result=system.info()
        elif a.module=='wifi' and a.action=='status': result=wifi.status()
        elif a.module=='wifi' and a.action=='audit': result=wifi.audit(a.interface)
        elif a.module=='wifi': result=wifi.pcap_metadata(a.file)
        elif a.module=='phishing' and a.action=='analyze': result=phishing.analyze(a.file)
        elif a.module=='phishing':
            content = phishing.template(a.scenario)
            if a.output:
                destination = Path(a.output).expanduser().resolve(); destination.parent.mkdir(parents=True, exist_ok=True); destination.write_text(content, encoding='utf-8'); print(f"Training template written to: {destination}")
            else:
                print(content, end='')
            return 0
        elif a.module=='api': result=api_discovery.discover(a.url,a.paths,a.timeout)
        elif a.module=='vulns':
            db=vulns.VulnerabilityDB(a.db); result=db.list(a.status) if a.action=='list' else {'id':db.add(a.title,a.severity,a.asset,a.evidence,a.remediation,a.status)}
        else: parser.error('unsupported command')
        write_report(result,getattr(a,'report',None))
        display = result
        if a.module == 'network' and a.action == 'scan' and not getattr(a, 'json', False):
            closed = [item for item in result.get('ports', []) if not item.get('open')]
            display = {key: value for key, value in result.items() if key != 'ports'}
            display['closed_or_filtered_ports'] = len(closed)
            display['open_port_details'] = [item for item in result.get('ports', []) if item.get('open')]
        emit(display,getattr(a,'json',False)); return 0 if not (isinstance(result,dict) and result.get('error')) else 2
    except (OSError, ValueError, FileNotFoundError, FileExistsError, json.JSONDecodeError) as exc:
        print(f'error: {exc}', file=sys.stderr); return 2

if __name__=='__main__': raise SystemExit(main())
