import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from contextlib import ExitStack, redirect_stderr
import io

from hackscan import main as scan_main
from tor_manager import check_route, ensure_tor, install_tor, start_local


class TorTests(unittest.TestCase):
    def session(self, payload=None, status=200):
        session=MagicMock()
        response=MagicMock(); response.status_code=status
        response.iter_content.return_value=[json.dumps(payload or {'IsTor':True,'IP':'DO_NOT_STORE'}).encode()]
        session.get.return_value.__enter__.return_value=response
        factory=MagicMock();factory.return_value.__enter__.return_value=session
        return factory,session,response

    def test_route_uses_proxy_remote_dns_and_excludes_ip(self):
        factory,session,_=self.session()
        with patch('tor_manager.proxy_preflight'),patch('tor_manager.requests.Session',factory):
            result=check_route('socks5h://127.0.0.1:9050')
        self.assertIs(session.trust_env,False)
        self.assertEqual(session.proxies['https'],'socks5h://127.0.0.1:9050')
        self.assertFalse(session.get.call_args.kwargs['allow_redirects'])
        self.assertTrue(result['is_tor'])
        self.assertNotIn('DO_NOT_STORE',json.dumps(result))

    def test_false_tor_blocks_without_fallback(self):
        factory,session,_=self.session({'IsTor':False})
        with patch('tor_manager.proxy_preflight'),patch('tor_manager.requests.Session',factory),self.assertRaisesRegex(RuntimeError,'scan bloqué'):
            check_route('socks5h://127.0.0.1:9050')
        session.get.assert_called_once()

    def test_socks_failure_prevents_http(self):
        with patch('tor_manager.proxy_preflight',side_effect=OSError('no proxy')),patch('tor_manager.requests.Session') as session,self.assertRaises(OSError):
            check_route('socks5h://127.0.0.1:9050')
        session.assert_not_called()

    def test_redirect_and_oversized_response_are_rejected(self):
        for status,body in [(302,b'{}'),(200,b'x'*8193)]:
            factory,_,response=self.session(status=status);response.iter_content.return_value=[body]
            with patch('tor_manager.proxy_preflight'),patch('tor_manager.requests.Session',factory),self.assertRaises(RuntimeError):
                check_route('socks5h://127.0.0.1:9050')

    def test_existing_proxy_is_reused_without_installation(self):
        with patch('tor_manager.port_in_use',return_value=True),patch('tor_manager.proxy_preflight'),patch('tor_manager.check_route',return_value={'is_tor':True}),patch('tor_manager.install_tor') as install,patch('tor_manager.start_local') as start:
            ensure_tor(wait=5)
        install.assert_not_called();start.assert_not_called()

    def test_missing_tor_is_installed_and_started(self):
        with patch('tor_manager.port_in_use',return_value=False),patch('tor_manager.shutil.which',return_value=None),patch('tor_manager.install_tor',return_value='/usr/bin/tor') as install,patch('tor_manager.start_local',return_value=Path('/tmp/test-tor')) as start,patch('tor_manager.check_route',return_value={'is_tor':True}):
            ensure_tor(port=9150,wait=5)
        install.assert_called_once();self.assertEqual(start.call_args.args[1],9150)

    def test_package_started_service_avoids_duplicate_instance(self):
        with patch('tor_manager.port_in_use',side_effect=[False,True]),patch('tor_manager.shutil.which',return_value=None),patch('tor_manager.install_tor',return_value='/usr/bin/tor'),patch('tor_manager.proxy_preflight'),patch('tor_manager.start_local') as start,patch('tor_manager.check_route',return_value={'is_tor':True}):
            ensure_tor(wait=5)
        start.assert_not_called()

    def test_check_only_never_installs(self):
        with patch('tor_manager.port_in_use',return_value=False),patch('tor_manager.install_tor') as install,self.assertRaisesRegex(RuntimeError,'Aucun proxy'):
            ensure_tor(check_only=True,wait=5)
        install.assert_not_called()

    def test_installer_uses_argument_arrays_and_sudo_only_for_packages(self):
        with patch('tor_manager.os.geteuid',return_value=1000),patch('tor_manager.sys.stdin.isatty',return_value=False),patch('tor_manager.shutil.which',side_effect=lambda cmd:'/usr/bin/'+cmd),patch('tor_manager.subprocess.run') as run:
            self.assertEqual(install_tor(),'/usr/bin/tor')
        self.assertEqual(run.call_args_list[0].args[0],['sudo','-n','apt-get','update'])
        self.assertEqual(run.call_args_list[1].args[0],['sudo','-n','apt-get','install','-y','--no-install-recommends','tor'])
        self.assertTrue(all(not c.kwargs.get('shell',False) for c in run.call_args_list))

    def test_local_config_is_private_verified_and_does_not_replace_existing(self):
        with tempfile.TemporaryDirectory() as folder,patch('tor_manager.subprocess.run') as run:
            directory=start_local('/usr/bin/tor',9150,folder)
            config=directory/'torrc'
            self.assertEqual(config.stat().st_mode&0o777,0o600)
            self.assertEqual(directory.stat().st_mode&0o777,0o700)
            text=config.read_text()
            self.assertIn('SocksPort 127.0.0.1:9150',text)
            self.assertIn('ClientOnly 1',text)
            self.assertIn('ControlPort 0',text)
            self.assertIn('--verify-config',run.call_args_list[0].args[0])
            config.write_text(text+'# personnalisation conservée\n')
            start_local('/usr/bin/tor',9150,folder)
            self.assertIn('personnalisation conservée',config.read_text())

    def test_generated_config_is_accepted_by_installed_tor(self):
        binary=shutil.which('tor')
        if not binary:self.skipTest('Tor non installé')
        with tempfile.TemporaryDirectory() as folder:
            with patch('tor_manager.subprocess.run'):
                directory=start_local(binary,9150,folder)
            result=subprocess.run([binary,'-f',str(directory/'torrc'),'--verify-config'],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_wrong_proxy_is_not_replaced_or_retried_directly(self):
        with patch('tor_manager.port_in_use',return_value=True),patch('tor_manager.proxy_preflight'),patch('tor_manager.check_route',side_effect=RuntimeError('ne confirme pas une sortie Tor')),patch('tor_manager.start_local') as start,self.assertRaises(RuntimeError):
            ensure_tor(wait=5)
        start.assert_not_called()

    def test_tor_failure_stops_before_any_target_request(self):
        with tempfile.TemporaryDirectory() as folder:
            argv=['hackscan.py','https://example.invalid/','--authorized','--tor','--profile','rapide','--config',str(Path(folder)/'prefs.json'),'--output',str(Path(folder)/'report')]
            with patch('sys.argv',argv),patch('hackscan.ensure_tor',side_effect=RuntimeError('Tor indisponible')),patch('hackscan.requests.Session.get') as get:
                self.assertEqual(scan_main(),1)
            get.assert_not_called()
            report=json.loads((Path(folder)/'report/report.json').read_text())
            self.assertEqual(report['requests'],[])
            self.assertEqual(report['status'],'incomplet')

    def test_custom_tor_port_passed_to_setup_and_scanner(self):
        with tempfile.TemporaryDirectory() as folder:
            argv=['hackscan.py','https://example.invalid/','--authorized','--tor','--tor-port','9150','--profile','rapide','--config',str(Path(folder)/'prefs.json'),'--output',str(Path(folder)/'report')]
            with patch('sys.argv',argv),patch('hackscan.ensure_tor',return_value={'status':'terminé','is_tor':True}) as ensure,patch('hackscan.proxy_preflight',return_value={'status':'disponible'}),patch('hackscan.Scanner.crawl'),patch('hackscan.Scanner.cms_checks'):
                self.assertEqual(scan_main(),0)
            ensure.assert_called_once_with(9150,90)
            report=json.loads((Path(folder)/'report/report.json').read_text())
            self.assertEqual(report['run_settings']['tor_port'],9150)

    def test_interactive_profile_equals_only_adds_target_type_input(self):
        with tempfile.TemporaryDirectory() as folder:
            argv=['hackscan.py','--interactive','--profile=rapide','--direct','--config',str(Path(folder)/'prefs.json'),'--output',str(Path(folder)/'report')]
            with patch('sys.argv',argv),patch('builtins.input',side_effect=['https://example.invalid/','o','']) as inputs,patch('hackscan.Scanner.crawl'),patch('hackscan.Scanner.cms_checks'),patch('hackscan.Scanner.sql_checks'),patch('hackscan.requests.Session.get') as get:
                self.assertEqual(scan_main(),0)
                self.assertEqual(inputs.call_count,3)
            get.assert_not_called()

    def test_abbreviated_explicit_tor_budgets_are_respected(self):
        with tempfile.TemporaryDirectory() as folder:
            argv=['hackscan.py','https://example.invalid/','--authorized','--tor','--profile=rapide','--timeo=5','--bud=15','--config',str(Path(folder)/'prefs.json'),'--output',str(Path(folder)/'report')]
            with patch('sys.argv',argv),patch('hackscan.ensure_tor',return_value={'status':'terminé','is_tor':True}),patch('hackscan.proxy_preflight',return_value={'status':'disponible'}),patch('hackscan.Scanner.crawl'),patch('hackscan.Scanner.cms_checks'):
                self.assertEqual(scan_main(),0)
            r=json.loads((Path(folder)/'report/report.json').read_text())
            self.assertEqual(r['configuration']['timeout_seconds'],5)
            self.assertEqual(r['configuration']['budget_seconds'],15)

    def test_custom_tor_port_survives_saved_preferences(self):
        with tempfile.TemporaryDirectory() as folder,ExitStack() as stack:
            ensure=stack.enter_context(patch('hackscan.ensure_tor',return_value={'status':'terminé','is_tor':True}))
            stack.enter_context(patch('hackscan.proxy_preflight',return_value={'status':'disponible'}))
            stack.enter_context(patch('hackscan.Scanner.crawl'))
            stack.enter_context(patch('hackscan.Scanner.cms_checks'))
            base=['hackscan.py','https://example.invalid/','--authorized','--profile=rapide','--config',str(Path(folder)/'prefs.json')]
            with patch('sys.argv',base+['--tor','--tor-port','9150','--save-config','--output',str(Path(folder)/'first')]):
                self.assertEqual(scan_main(),0)
            self.assertEqual(json.loads((Path(folder)/'prefs.json').read_text())['tor_port'],9150)
            with patch('sys.argv',base+['--output',str(Path(folder)/'second')]):
                self.assertEqual(scan_main(),0)
            self.assertEqual(ensure.call_args.args[0],9150)

    def test_invalid_saved_tor_values_fail_without_traceback_or_network(self):
        for setting in [{'profile':'rapide','tor':True,'timeout':'incorrect'}, {'profile':'rapide','tor':True,'tor_port':'incorrect'}]:
            with self.subTest(setting=setting),tempfile.TemporaryDirectory() as folder:
                config=Path(folder)/'prefs.json';config.write_text(json.dumps(setting))
                argv=['hackscan.py','https://example.invalid/','--authorized','--config',str(config)]
                err=io.StringIO()
                with patch('sys.argv',argv),patch('hackscan.ensure_tor') as ensure,redirect_stderr(err),self.assertRaises(SystemExit) as result:
                    scan_main()
                self.assertEqual(result.exception.code,2)
                self.assertNotIn('Traceback',err.getvalue())
                ensure.assert_not_called()


if __name__=='__main__':unittest.main()
