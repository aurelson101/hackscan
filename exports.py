"""Exports de direction, registre modifiable et PDF A4 autonome."""
import csv
import hashlib
import html
import io
import json
from pathlib import Path
from report_v4 import additional_exports, pdf_analysis
from presentation import executive_page


def csv_safe(value):
    text = str(value if value is not None else '')
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def csv_register(report):
    stream = io.StringIO(newline='')
    fields = ['id', 'key', 'severity', 'qualification', 'title', 'component', 'url', 'owner', 'proposed_due_date', 'treatment_status', 'decision', 'validator', 'closure_evidence', 'remediation', 'theme', 'evidence_level', 'triage', 'effort', 'dependencies', 'evidence_age_days', 'evidence_ids']
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    writer.writerows({key: csv_safe(row.get(key, '')) for key in fields} for row in report['risk_register'])
    return '\ufeff' + stream.getvalue()


def sarif(report):
    rules, results = [], []
    for finding in report['risk_register']:
        rule_id = finding['key']
        rules.append({'id': rule_id, 'shortDescription': {'text': finding['title']},
                      'help': {'text': finding['remediation']}, 'properties': {'confidence': finding.get('confidence')}})
        results.append({'ruleId': rule_id, 'level': {'Critique':'error','Haute':'error','Moyenne':'warning','Faible':'note','Info':'note'}.get(finding['severity'],'note'),
                        'message': {'text': finding['evidence']},
                        'locations': [{'physicalLocation': {'artifactLocation': {'uri': finding.get('url', report['target'])}}}]})
    return json.dumps({'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json',
                       'runs':[{'tool':{'driver':{'name':'Hackscan','version':'5.0','rules':rules}},'results':results}]}, ensure_ascii=False, indent=2)


def cyclonedx(report):
    components = []
    for kind in ('plugins', 'themes'):
        for name, item in report.get('inventory', {}).get(kind, {}).items():
            versions = item.get('versions') or []
            components.append({'type':'application','name':name,'version':versions[0] if len(versions)==1 else 'unknown',
                               'properties':[{'name':'hackscan:component-kind','value':kind},
                                             {'name':'hackscan:version-confidence','value':'déclarative à confirmer'}]})
    return json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':components}, ensure_ascii=False, indent=2)


def executive_html(report):
    return executive_page(report)


def build_pdf(report, output):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    font_dir = Path('/usr/share/fonts/truetype/dejavu')
    if (font_dir/'DejaVuSans.ttf').exists():
        pdfmetrics.registerFont(TTFont('Audit', str(font_dir/'DejaVuSans.ttf')))
        pdfmetrics.registerFont(TTFont('AuditBold', str(font_dir/'DejaVuSans-Bold.ttf')))
        pdfmetrics.registerFontFamily('Audit', normal='Audit', bold='AuditBold')
        font, bold = 'Audit', 'AuditBold'
    else:
        font, bold = 'Helvetica', 'Helvetica-Bold'
    styles = getSampleStyleSheet()
    for style in styles.byName.values():
        style.fontName = font
    styles['Normal'].fontSize = 9
    styles['Normal'].leading = 13
    styles['Normal'].wordWrap = 'CJK'
    styles['Heading1'].fontName = styles['Heading2'].fontName = bold
    styles['Heading1'].textColor = colors.HexColor('#154e7b')
    styles.add(ParagraphStyle('SmallAudit', parent=styles['Normal'], fontSize=7, leading=10))
    story = []
    p = lambda text, style='Normal': Paragraph(html.escape(str(text)).replace('\n', '<br/>'), styles[style])
    def heading(text):
        story.extend([Spacer(1, 10), p(text, 'Heading1')])
    def rows(headers, values, widths=None):
        if not values:
            story.append(p('Aucune observation enregistrée dans ce périmètre.'))
            return
        data = [[p(cell, 'SmallAudit') for cell in headers]] + [[p(cell, 'SmallAudit') for cell in row] for row in values]
        width = A4[0]-88
        grid = Table(data, colWidths=widths or [width/len(headers)]*len(headers), repeatRows=1, hAlign='LEFT')
        grid.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e8eff7')), ('VALIGN', (0,0), (-1,-1), 'TOP'), ('GRID', (0,0), (-1,-1), .3, colors.HexColor('#d5dfeb')), ('LEFTPADDING', (0,0),(-1,-1),5), ('RIGHTPADDING',(0,0),(-1,-1),5), ('TOPPADDING',(0,0),(-1,-1),5), ('BOTTOMPADDING',(0,0),(-1,-1),5)]))
        story.append(grid)
    meta = report['metadata']
    is_router = report.get('asset_profile', {}).get('kind') == 'routeur'
    document_title = 'Rapport de pentest routeur — RSSI / CISO' if is_router else 'Rapport de sécurité web — RSSI / CISO'
    story += [p(document_title, 'Title'), Spacer(1, 16), p(meta['organization'], 'Heading1'), p(report['target']), p(meta['classification']), p(meta['validation']), p('Version '+meta['version']+' · Collecte : '+str(report.get('started_utc', ''))), p('Responsable : '+meta['owner'])]
    heading('1. Synthèse décisionnelle')
    story += [p('Statut : '+report.get('status', 'non enregistré')), p('Constats : '+str(report['summary']['finding_count'])+' · Obstacles : '+str(report['summary']['obstacle_count'])), p('Valider la qualification métier, attribuer les responsables et planifier les recontrôles. Aucun score global ni absence de compromission n’est déduit de ce scan.')]
    if report['analysis_obstacles']:
        rows(['Obstacle', 'Conséquence', 'Action proposée'], [[o['cause'], o['impact'], o['action']] for o in report['analysis_obstacles']])
    else:
        story.append(p('Aucun obstacle technique enregistré dans la collecte ; les exclusions et inconnues restent détaillées dans la couverture.'))
    heading('2. Périmètre et contexte')
    rows(['Paramètre', 'Valeur'], [['URL demandée', report.get('requested_target', report['target'])], ['URL évaluée', report['target']], ['Transport', report.get('proxy')], ['Fin de collecte UTC', report.get('finished_utc')]] + [[k, v] for k, v in report.get('business_context', {}).items()] + [[k,v] for k,v in report.get('configuration', {}).items()])
    heading('3. Couverture effective')
    rows(['Domaine', 'État', 'Observations', 'Limites'], report['coverage'])
    if not report['risk_register']:
        heading('4. Constats et qualification')
        story.append(p('Aucun constat dans le périmètre effectivement observé.'))
    for index, f in enumerate(report['risk_register']):
        start = len(story)
        if index == 0:
            heading('4. Constats et qualification')
        story.append(p(f['id']+' — '+f['title'], 'Heading2'))
        for label, key in [('Priorité', 'severity'), ('Qualification', 'qualification'), ('Source', 'url'), ('Preuve', 'evidence'), ('Impact potentiel', 'impact'), ('Conditions', 'condition'), ('Remédiation', 'remediation'), ('Responsable', 'owner'), ('Échéance proposée', 'proposed_due_date'), ('Statut', 'treatment_status'), ('Preuve de clôture attendue', 'closure')]:
            story.append(p(label+' : '+str(f.get(key, 'non renseigné'))))
        if f.get('closure_evidence'):
            story.append(p('Preuve de clôture déclarée : '+f['closure_evidence']))
        story.append(p('Triage proposé : '+f['triage']+' · '+f['evidence_level']))
        story.append(p('Justification : '+' ; '.join(f['triage_reasons'])))
        story.append(p('Index des preuves : '+', '.join(f['evidence_ids'])))
        if f.get('cves'):
            story.append(p('CVE fournies par la source : '+', '.join(f['cves'])))
        if f.get('fixed_in'):
            story.append(p('Version corrigée selon la source : '+str(f['fixed_in'])))
        story[start:] = [KeepTogether(story[start:])]
    heading('5. Inventaire et mesures')
    if is_router:
        rows(['Route', 'HTTP', 'Format', 'Éléments racine', 'Liste max.', 'Champs autorisés'],
             [[row.get('path',''), row.get('http_status',''), row.get('format',''), row.get('items',0), row.get('max_list_items',0), ', '.join(row.get('keys',[]))]
              for row in report.get('router_inventory', [])])
        story.append(p('Les valeurs IP, MAC, noms d’hôtes, SSID, jetons et corps de réponse sont exclus.'))
    else:
        items = [[kind, name, ', '.join(item.get('versions', [])) or 'inconnue', item.get('readme_stable_tag','inconnu')] for kind in ('plugins','themes') for name,item in report.get('inventory', {}).get(kind, {}).items()]
        rows(['Type', 'Composant', 'Version déclarée', 'Stable tag'], items)
        rows(['CMS', 'Versions publiquement déclarées'], [[name, ', '.join(versions) or 'inconnue'] for name,versions in report.get('cms_versions', {}).items()])
    tls = report.get('tools', {}).get('tls', {})
    rows(['TLS demandé', 'État', 'Suite négociée', 'Expiration'], [[h.get('requested'), h['status'], str(h.get('cipher','non négociée')), h.get('not_after','inconnue')] for h in tls.get('handshakes', [])])
    certificates = {h['certificate_sha256']: h for h in tls.get('handshakes', []) if h.get('certificate_sha256')}
    for digest, cert in certificates.items():
        story.extend([p('Émetteur : '+str(cert.get('issuer','inconnu'))),
                      p('Noms DNS du certificat : '+', '.join(cert.get('subject_alt_names',[]))),
                      p('Empreinte SHA-256 du certificat : '+digest),
                      p('Chaîne vérifiée : '+str(cert.get('verified_chain_length','inconnue'))+' certificats ; expiration : '+str(cert.get('not_after','inconnue')))])
    rows(['Cookie (sans valeur)', 'Secure', 'HttpOnly', 'SameSite'], [[c['name'],c['secure'],c['http_only'],c['same_site']] for c in report.get('cookies', [])])
    rows(['Composant', 'Version éditeur', 'Qualification'], [[c['component'],c.get('latest','inconnue'),c['status']] for c in report.get('tools', {}).get('references', {}).get('components',[])])
    for component in report.get('tools', {}).get('references', {}).get('components',[]):
        story.append(p('Source éditeur — '+component['component']+' : '+component['source'],'SmallAudit'))
    heading('6. Plan de traitement')
    rows(['ID', 'Responsable', 'Échéance', 'Statut / décision'], [[f['id'],f['owner'],f['proposed_due_date'],f['treatment_status']+' / '+f.get('decision','à décider')] for f in report['risk_register']])
    story.append(p('Les affectations et échéances sont proposées. Les déclarations saisies par l’utilisateur ne constituent pas une validation technique automatique.'))
    heading('7. Annexes et traçabilité')
    rows(['Contrôle', 'État', 'Preuve'], [[c.get('category','')+' / '+c.get('name',''),c.get('status',''),c.get('evidence','')] for c in report.get('checks', [])])
    rows(['URL', 'HTTP', 'Erreur'], [[q['url'], q.get('status'), q.get('error','')] for q in report.get('requests',[])])
    for name,data in report.get('tools', {}).items():
        story.append(p(name+' : '+data.get('status','non enregistré')+' — '+str(data.get('detail') or data.get('conclusion') or '' )))
    for limitation in report.get('limitations', []):
        story.append(p('• '+limitation))
    sources = 'https://owasp.org/www-project-web-security-testing-guide/' if is_router else 'https://owasp.org/www-project-web-security-testing-guide/ ; https://github.com/wpscanteam/wpscan ; https://github.com/sqlmapproject/sqlmap/wiki/Usage'
    story.append(p('Sources méthodologiques : '+sources))
    story.append(p('Les annexes JSON/HTML conservent les empreintes des réponses, les journaux d’outils et les références éditeur. manifest.sha256 permet de vérifier les exports.'))
    pdf_analysis(report, heading, rows, story, p)
    def footer(canvas, document):
        canvas.setFont(font, 7)
        canvas.setFillColor(colors.HexColor('#50627a'))
        canvas.drawString(44, 24, 'Hackscan · '+meta['classification'])
        canvas.drawRightString(A4[0]-44, 24, 'Page '+str(document.page))
    path = Path(output)/'report.pdf'
    SimpleDocTemplate(str(path), pagesize=A4, rightMargin=44, leftMargin=44, topMargin=40, bottomMargin=42, title=document_title, author=meta['owner']).build(story, onFirstPage=footer, onLaterPages=footer)
    path.chmod(0o600)


def extra_html(report):
    e = lambda value: html.escape(str(value), quote=True)
    text = '<section id="evolutions"><h2>8. Contrôles complémentaires et suivi</h2>'
    text += '<h3>Versions éditeur</h3>'
    for item in report.get('tools', {}).get('references', {}).get('components', []):
        text += '<div class="panel"><b>'+e(item['component'])+'</b> · publiée : '+e(item.get('latest','inconnue'))+'<p>'+e(item['status'])+'</p><p>'+e(item.get('detail') or item['cve_status'])+'</p><small>Source : '+e(item['source'])+'</small></div>'
    text += '<h3>Transport TLS détaillé</h3><pre>'+e(json.dumps(report.get('tools', {}).get('tls', {}), ensure_ascii=False, indent=2))+'</pre><h3>Cookies — valeurs exclues</h3><pre>'+e(json.dumps(report.get('cookies', []),ensure_ascii=False,indent=2))+'</pre>'
    comparison = report.get('comparison')
    if comparison:
        text += '<h3>Évolution depuis le précédent audit</h3><p>'+e(comparison['conclusion'])+'</p>'
        for key,label in [('new','Nouveaux'),('persistent','Persistants'),('regressions','Priorité augmentée'),('not_observed','Non observés — clôture non déduite')]:
            text += '<h4>'+label+' ('+str(len(comparison[key]))+')</h4><ul>'+''.join('<li>'+e(f['title'])+'</li>' for f in comparison[key])+'</ul>'
    text += '<h3>Édition du plan de traitement</h3><p>Les modifications sont locales au navigateur. Exportez le plan pour le conserver ; aucun changement applicatif ni validation automatique. Une confirmation humaine ou une acceptation proposée nécessite un validateur et une preuve/justification à la réimportation.</p><button type="button" id="export-plan">Télécharger le plan JSON édité</button><div class="table"><table><thead><tr><th>ID</th><th>Qualification</th><th>Responsable</th><th>Échéance</th><th>Statut</th><th>Décision proposée</th><th>Validateur</th><th>Preuve / justification</th></tr></thead><tbody>'
    for f in report['risk_register']:
        text += '<tr class="plan-row" data-key="'+e(f['key'])+'"><td>'+e(f['id'])+'</td>'
        for key,kind in [('qualification','text'),('owner','text'),('proposed_due_date','date'),('treatment_status','text'),('decision','text'),('validator','text'),('closure_evidence','text')]:
            text += '<td><input aria-label="'+e(f['id']+' '+key)+'" data-field="'+key+'" type="'+kind+'" maxlength="2000" value="'+e(f.get(key,''))+'"></td>'
        text += '</tr>'
    text += '</tbody></table></div><h3>Historique de reprise</h3><pre>'+e(json.dumps(report.get('resume_history', []),ensure_ascii=False,indent=2))+'</pre></section>'
    text += '<script type="application/json" id="risk-data">'+json.dumps(report['risk_register'], ensure_ascii=False).replace('<', chr(92) + 'u003c')+'</script>'
    text += '''<script>
const risks=JSON.parse(document.getElementById('risk-data').textContent);
function applyFilters(){const query=document.getElementById('risk-search').value.toLocaleLowerCase();const severity=document.getElementById('risk-severity').value;const qualification=document.getElementById('risk-qualification').value;const status=document.getElementById('risk-status').value;let visible=0;document.querySelectorAll('.finding[data-key]').forEach(card=>{const f=risks.find(r=>r.key===card.dataset.key);const show=(!severity||f.severity===severity)&&(!qualification||f.qualification===qualification)&&(!status||f.treatment_status===status)&&JSON.stringify(f).toLocaleLowerCase().includes(query);card.hidden=!show;if(show)visible++;});document.getElementById('filter-count').textContent=visible+' / '+risks.length+' constats affichés';}
for(const id of ['risk-search','risk-severity','risk-qualification','risk-status'])document.getElementById(id).addEventListener('input',applyFilters);
document.querySelectorAll('.plan-row input').forEach(input=>input.addEventListener('input',()=>{const row=risks.find(r=>r.key===input.closest('tr').dataset.key);row[input.dataset.field]=input.value;for(const [field,id] of [['treatment_status','risk-status'],['qualification','risk-qualification']]){const select=document.getElementById(id);const previous=select.value;const values=Array.from(new Set(risks.map(r=>r[field]))).sort();select.replaceChildren(new Option('Tous',''),...values.map(v=>new Option(v,v)));select.value=values.includes(previous)?previous:'';}applyFilters();}));
document.getElementById('export-plan').addEventListener('click',()=>{const entries=risks.map(f=>({key:f.key,qualification:f.qualification,owner:f.owner,proposed_due_date:f.proposed_due_date,treatment_status:f.treatment_status,decision:f.decision||'',validator:f.validator||'',closure_evidence:f.closure_evidence||''}));const url=URL.createObjectURL(new Blob([JSON.stringify({schema:1,entries},null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='treatment-plan.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});applyFilters();
</script>'''
    return text


def filters_html(report):
    e = lambda value: html.escape(str(value), quote=True)
    text = '<div class="panel filters"><label>Rechercher un constat, composant ou responsable <input id="risk-search" type="search"></label>'
    for key,field,label in [('severity','severity','Priorité'),('qualification','qualification','Qualification'),('status','treatment_status','Statut')]:
        text += '<label>'+label+' <select id="risk-'+key+'"><option value="">Tous</option>'+''.join('<option value="'+e(v)+'">'+e(v)+'</option>' for v in sorted({r[field] for r in report['risk_register']}))+'</select></label>'
    return text + '<p id="filter-count" aria-live="polite"></p></div>'


def export_files(report, output):
    output = Path(output)
    for name,content in [('executive.html', executive_html(report)), ('risk-register.csv', csv_register(report)),
                         ('findings.sarif.json', sarif(report)), ('components.cdx.json', cyclonedx(report)),
                         ('treatment-plan.json', json.dumps({'schema':1,'entries':[{k:f.get(k,'') for k in ('key','qualification','owner','proposed_due_date','treatment_status','decision','validator','closure_evidence')} for f in report['risk_register']]},ensure_ascii=False,indent=2))]:
        path = output/name
        path.write_text(content,encoding='utf-8')
        path.chmod(0o600)
    build_pdf(report,output)
    additional_exports(report, output, csv_safe)
