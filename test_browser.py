"""Vérification optionnelle Firefox : filtres, plan édité, téléchargements et responsive."""
import argparse
import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time


def main():
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service
    from selenium.webdriver.support.ui import Select
    from selenium.webdriver.support.ui import WebDriverWait
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report_directory',type=Path)
    parser.add_argument('--output',type=Path,default=Path('reports/browser-validation'))
    args=parser.parse_args()
    folder=args.report_directory.resolve()
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=True,mode=0o700)
    downloads=output/'downloads'; downloads.mkdir(exist_ok=True,mode=0o700)
    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),functools.partial(QuietHandler,directory=str(folder)))
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    options=Options(); options.add_argument('-headless')
    snap_binary=Path('/snap/firefox/current/usr/lib/firefox/firefox')
    if snap_binary.exists():
        options.binary_location=str(snap_binary)
    options.set_preference('browser.download.folderList',2)
    options.set_preference('browser.download.dir',str(downloads))
    options.set_preference('browser.helperApps.neverAsk.saveToDisk','application/pdf,application/json,text/csv,application/octet-stream')
    options.set_preference('pdfjs.disabled',True)
    profile_root=Path.home()/'snap/firefox/common'
    plain_driver=Path('/snap/firefox/current/usr/lib/firefox/geckodriver')
    service=Service(executable_path=str(plain_driver) if plain_driver.exists() else None,
                    service_args=['--profile-root',str(profile_root)] if profile_root.exists() else [],
                    log_output=str(output/'geckodriver.log'))
    driver=None
    def downloaded(name):
        path=downloads/name
        for _ in range(100):
            if path.exists() and not Path(str(path)+'.part').exists() and path.stat().st_size:
                return path
            time.sleep(.1)
        raise AssertionError('Téléchargement manquant : '+name)
    try:
        driver=webdriver.Firefox(service=service,options=options)
        driver.set_window_size(1440,1200)
        driver.get('http://127.0.0.1:'+str(server.server_port)+'/report.html')
        driver.execute_script('document.documentElement.style.scrollBehavior="auto"')
        risks=json.loads(driver.find_element(By.ID,'risk-data').get_attribute('textContent'))
        assert len(driver.find_elements(By.CSS_SELECTOR,'.finding[data-key]'))==len(risks)
        if driver.find_elements(By.ID,'direction-report'):
            before=driver.current_url.split('#')[0]
            button=driver.find_element(By.CSS_SELECTOR,'button[data-report-view="direction"]')
            button.click()
            assert driver.current_url.split('#')[0]==before
            assert driver.find_element(By.ID,'direction-report').is_displayed()
            assert not driver.find_element(By.ID,'constats').is_displayed()
            assert button.get_attribute('aria-pressed')=='true'
            technical=driver.find_element(By.CSS_SELECTOR,'button[data-report-view="technical"]')
            assert technical.get_attribute('aria-pressed')=='false'
            assert button.value_of_css_property('background-color')!=technical.value_of_css_property('background-color')
            driver.execute_script('document.getElementById("direction-report").scrollIntoView()')
            driver.save_screenshot(str(output/'direction-desktop.png'))
            driver.set_window_size(390,844)
            driver.execute_script('window.scrollTo(0,0)')
            assert driver.execute_script('return document.documentElement.scrollWidth <= window.innerWidth')
            driver.save_screenshot(str(output/'direction-mobile.png'))
            driver.set_window_size(1440,1200)
            link=driver.find_element(By.CSS_SELECTOR,'#direction-report a[data-report-view="technical"]')
            driver.execute_script('arguments[0].scrollIntoView()',link);link.click()
            assert driver.find_element(By.ID,'constats').is_displayed()
            assert not driver.find_element(By.ID,'direction-report').is_displayed()
        if driver.find_elements(By.ID,'control-matrix'):
            controls=driver.find_elements(By.CSS_SELECTOR,'.control-row')
            expected_controls=json.loads((folder/'intelligence.json').read_text(encoding='utf-8'))['controls']
            assert len(controls)==len(expected_controls)
            field=driver.find_element(By.ID,'control-search')
            driver.execute_script('arguments[0].scrollIntoView()',field)
            field.send_keys(controls[0].get_attribute('id'))
            assert len(driver.find_elements(By.CSS_SELECTOR,'.control-row:not([hidden])'))==1
            field.clear()
            domain=controls[0].get_attribute('data-domain')
            Select(driver.find_element(By.ID,'control-domain')).select_by_value(domain)
            assert len(driver.find_elements(By.CSS_SELECTOR,'.control-row:not([hidden])'))==sum(c.get_attribute('data-domain')==domain for c in controls)
            Select(driver.find_element(By.ID,'control-domain')).select_by_value('')
            state=controls[0].get_attribute('data-state')
            Select(driver.find_element(By.ID,'control-state')).select_by_value(state)
            assert len(driver.find_elements(By.CSS_SELECTOR,'.control-row:not([hidden])'))==sum(c.get_attribute('data-state')==state for c in controls)
            Select(driver.find_element(By.ID,'control-state')).select_by_value('')
            Select(driver.find_element(By.ID,'audience')).select_by_value('direction')
            assert not driver.find_element(By.ID,'control-matrix').is_displayed()
            assert driver.find_element(By.ID,'intelligence').is_displayed()
            link=driver.find_element(By.CSS_SELECTOR,'a[href="#constats"]')
            driver.execute_script('arguments[0].scrollIntoView()',link);link.click()
            assert driver.find_element(By.ID,'constats').is_displayed(), 'Le sommaire pointe vers une section masquée en lecture direction'
            Select(driver.find_element(By.ID,'audience')).select_by_value('direction')
            Select(driver.find_element(By.ID,'audience')).select_by_value('full')
            assert driver.find_element(By.ID,'control-matrix').is_displayed()
        if risks:
            search=driver.find_element(By.ID,'risk-search'); search.send_keys(risks[0]['key'])
            assert len(driver.find_elements(By.CSS_SELECTOR,'.finding:not([hidden])'))==1
            search.clear()
            Select(driver.find_element(By.ID,'risk-severity')).select_by_value(risks[-1]['severity'])
            assert len(driver.find_elements(By.CSS_SELECTOR,'.finding:not([hidden])'))==sum(r['severity']==risks[-1]['severity'] for r in risks)
            Select(driver.find_element(By.ID,'risk-severity')).select_by_value('')
            row=driver.find_elements(By.CSS_SELECTOR,'.plan-row')[0]
            driver.execute_script('arguments[0].scrollIntoView()',row)
            for field,value in [('owner','TEST navigateur — à remplacer'),('treatment_status','En cours (test)'),('validator','TEST RSSI'),('decision','corriger'),('closure_evidence','TEST : recontrôle à réaliser')]:
                element=row.find_element(By.CSS_SELECTOR,'input[data-field="'+field+'"]'); element.clear(); element.send_keys(value)
            Select(driver.find_element(By.ID,'risk-status')).select_by_value('En cours (test)')
            assert len(driver.find_elements(By.CSS_SELECTOR,'.finding:not([hidden])'))==1
            if driver.find_elements(By.ID,'plan-dirty'):
                assert driver.find_element(By.ID,'plan-dirty').is_displayed()
            button=driver.find_element(By.ID,'export-plan'); driver.execute_script('arguments[0].scrollIntoView()',button); button.click()
            plan=json.loads(downloaded('treatment-plan.json').read_text())
            assert plan['entries'][0]['owner']=='TEST navigateur — à remplacer'
            assert plan['entries'][0]['treatment_status']=='En cours (test)'
            if driver.find_elements(By.ID,'plan-dirty'):
                assert not driver.find_element(By.ID,'plan-dirty').is_displayed()
            Select(driver.find_element(By.ID,'risk-status')).select_by_value('')
        export_names=['report.pdf','risk-register.csv']
        if driver.find_elements(By.ID,'control-matrix'): export_names+=['controls.csv','intelligence.json']
        if driver.find_elements(By.ID,'direction-report'): export_names+=['executive.html','manifest.sha256']
        for name in export_names:
            link=driver.find_element(By.CSS_SELECTOR,'a[href="'+name+'"]'); driver.execute_script('arguments[0].scrollIntoView()',link); link.click()
            actual=downloaded(name)
            assert hashlib.sha256(actual.read_bytes()).digest()==hashlib.sha256((folder/name).read_bytes()).digest()
        driver.execute_script('document.getElementById("constats").scrollIntoView()')
        driver.save_screenshot(str(output/'desktop-findings.png'))
        driver.set_window_size(390,844)
        driver.execute_script('window.scrollTo(0,0)')
        assert driver.execute_script('return document.documentElement.scrollWidth <= window.innerWidth')
        driver.save_screenshot(str(output/'mobile.png'))
        if driver.find_elements(By.ID,'intelligence'):
            driver.set_window_size(1440,1100)
            driver.execute_script('document.getElementById("intelligence").scrollIntoView()')
            driver.save_screenshot(str(output/'intelligence.png'))
            driver.execute_script('document.getElementById("control-matrix").scrollIntoView()')
            driver.save_screenshot(str(output/'controls.png'))
            driver.get('http://127.0.0.1:'+str(server.server_port)+'/improvements.html')
            assert len(driver.find_elements(By.CSS_SELECTOR,'tbody tr'))==100
            if driver.find_elements(By.ID,'direction-report')==[] and driver.find_elements(By.CSS_SELECTOR,'a[href="report.html#direction-report"]'):
                driver.set_window_size(390,844)
                assert driver.execute_script('return document.documentElement.scrollWidth <= window.innerWidth')
                driver.save_screenshot(str(output/'catalogue-mobile.png'))
                link=driver.find_element(By.CSS_SELECTOR,'a[href="report.html#direction-report"]');link.click()
                assert driver.find_element(By.ID,'direction-report').is_displayed()
        driver.get('http://127.0.0.1:'+str(server.server_port)+'/executive.html')
        assert 'Synthèse de sécurité' in driver.title or 'Synthèse' in driver.find_element(By.TAG_NAME,'h1').text
        driver.execute_script('document.documentElement.style.scrollBehavior="auto";window.scrollTo(0,0)')
        driver.set_window_size(1440,1100)
        driver.save_screenshot(str(output/'executive-standalone.png'))
        driver.set_window_size(390,844)
        assert driver.execute_script('return document.documentElement.scrollWidth <= window.innerWidth')
        driver.save_screenshot(str(output/'executive-mobile.png'))
        link=driver.find_element(By.CSS_SELECTOR,'a[href="report.html"]');link.click()
        assert driver.find_element(By.ID,'constats').is_displayed()
        driver.get((folder/'report.html').as_uri())
        driver.find_element(By.CSS_SELECTOR,'button[data-report-view="direction"]').click()
        assert driver.current_url.startswith('file:') and driver.find_element(By.ID,'direction-report').is_displayed()
        driver.set_window_size(700,1100)
        small_url='http://127.0.0.1:'+str(server.server_port)+'/report.html#direction-report'
        driver.execute_script('const frame=document.createElement("iframe");frame.id="small-viewport";frame.style="width:360px;height:950px;border:0";frame.src=arguments[0];document.body.replaceChildren(frame);',small_url)
        frame=driver.find_element(By.ID,'small-viewport')
        driver.switch_to.frame(frame)
        WebDriverWait(driver,10).until(lambda d: len(d.find_elements(By.ID,'direction-report')) and d.find_element(By.ID,'direction-report').is_displayed())
        assert driver.execute_script('return window.innerWidth')==360
        assert driver.execute_script('return document.documentElement.scrollWidth <= window.innerWidth')
        driver.switch_to.default_content()
        frame.screenshot(str(output/'direction-360.png'))
        driver.switch_to.frame(frame)
        driver.find_element(By.CSS_SELECTOR,'button[data-report-view="technical"]').click()
        assert driver.find_element(By.ID,'constats').is_displayed()
        assert driver.execute_script('return document.documentElement.scrollWidth <= window.innerWidth'), driver.execute_script('return [...document.querySelectorAll("main > *, .panel > *, .finding > *")].filter(e=>e.getBoundingClientRect().right>window.innerWidth).map(e=>[e.tagName,e.id,e.className,Math.round(e.getBoundingClientRect().right)])')
        driver.switch_to.default_content()
        print('Firefox : filtres constats/contrôles, lecture direction, plan édité, téléchargements, catalogue et mobile validés.')
    finally:
        if driver: driver.quit()
        server.shutdown(); server.server_close(); thread.join()


if __name__=='__main__':
    main()
