"""Présentation décisionnelle et exports d'intelligence de sécurité."""
import csv
import html
import io
import json
from pathlib import Path

from intelligence import CATALOGUE, SOURCES
from presentation import styles


def e(value):
    return html.escape(str(value), quote=True)


def grid(headers, rows):
    return '<div class="table"><table><thead><tr>'+''.join('<th scope="col">'+e(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+e(c)+'</td>' for c in row)+'</tr>' for row in rows)+'</tbody></table></div>'


def intelligence_html(report):
    a=report['intelligence']
    control_total=len(a['controls'])
    text='<section id="intelligence"><h2>Analyse explicable et décisions</h2><p>'+e(a['engine'])+'. Chaque recommandation renvoie aux mesures collectées. Les impacts métier restent à valider.</p>'
    text+='<div class="audience-switch panel"><label>Mode de lecture <select id="audience"><option value="full">RSSI / technique — complet</option><option value="direction">Direction — décisions et feuille de route</option></select></label></div>'
    text+='<div class="metrics">'
    for state in ('à revoir','observé','inconnu','non applicable'):
        text+='<div class="metric"><strong>'+str(a['control_counts'].get(state,0))+'</strong>Contrôles '+e(state)+'</div>'
    text+='</div><div class="panel"><h3>Répartition des '+str(control_total)+' contrôles</h3><svg viewBox="0 0 600 56" role="img" aria-labelledby="coverage-title coverage-description"><title id="coverage-title">Couverture des contrôles</title><desc id="coverage-description">'+e('; '.join(k+': '+str(v) for k,v in a['control_counts'].items()))+'. Ce diagramme ne mesure pas la sécurité.</desc>'
    position=0
    colors={'à revoir':'#a65c00','observé':'#216983','inconnu':'#66778a','non applicable':'#a5b5c5'}
    for state,color in colors.items():
        width=(a['control_counts'].get(state,0)*600/control_total) if control_total else 0
        if width:
            text+='<rect x="'+str(position)+'" y="4" width="'+str(width)+'" height="34" fill="'+color+'"/>'
        position+=width
    text+='</svg><p>'+e(a['assurance'])+'</p><p>« Observé » signifie qu’aucun indice de la règle concernée n’a été relevé dans l’échantillon, sans garantie sur les parcours non parcourus. « À revoir » demande une qualification ; ce n’est pas une exploitation confirmée.</p></div>'
    text+='<h3>Décisions proposées</h3><div class="decision-grid">'
    for d in a['decisions']:
        text+='<article class="panel"><h4>'+e(d['title'])+'</h4><p><b>Pourquoi :</b> '+e(d['reason'])+'</p><p><b>Action :</b> '+e(d['action'])+'</p><p><b>Responsable proposé :</b> '+e(d['owner'])+'</p><p><b>Mesure conservatoire :</b> '+e(d['conservative_measure'])+'</p></article>'
    text+='</div><h3>Feuille de route par cause</h3>'
    text+=grid(['Cause / IDs','Fenêtre proposée','Responsable','Action et dépendance','Clôture'],[[g['theme']+' / '+', '.join(g['finding_ids']+g['control_ids']),g['window'],g['owner'],g['action']+'\nPrérequis : '+g['validation']+'\nEffort : '+g['effort'],g['closure']] for g in a['roadmap']])
    text+=grid(['Campagne','Objectif proposé'],[[c['window'],c['action']] for c in a['campaigns']])
    text+='<h3>Preuves internes à obtenir</h3>'+grid(['Domaine','Responsable proposé','Preuve attendue','Statut'],[[c['domain'],c['owner'],c['proof'],c['state']] for c in a['internal_evidence']])
    text+='<h3>Qualité des données et des déclarations</h3><p>Âge des mesures : '+str(a['evidence_age_days'])+' jour(s). Regroupement : '+str(a['deduplication']['raw_findings'])+' observations → '+str(a['deduplication']['grouped_findings'])+' constats → '+str(a['deduplication']['action_groups'])+' causes de traitement.</p><ul>'+''.join('<li>'+e(g)+'</li>' for g in a['gaps']+a['contradictions'])+'</ul>'
    text+=grid(['ID en retard','Jours après échéance proposée','Responsable'],[[d['id'],d['days_overdue'],d['owner']] for d in a['deadline_alerts']])
    text+='<div class="technical-detail"><h3>Matrice par domaine</h3>'+grid(['Domaine','À revoir','Observé','Inconnu','Non applicable'],[[d]+[s.get(k,0) for k in ('à revoir','observé','inconnu','non applicable')] for d,s in a['domain_matrix'].items()])
    text+='<h3>Mesures réseau côté client</h3><p>'+e(a['network']['meaning'])+'</p>'+grid(['Mesure','Valeur'],[['Requêtes mesurées',a['network']['measured_requests']],['Médiane (ms)',a['network']['median_ms']],['P95 (ms)',a['network']['p95_ms']],['Réponses HTTP',a['network']['http_counts']]])
    text+='<div id="control-matrix"><h3>Registre complet des '+str(control_total)+' contrôles</h3><p>Sources : <a href="'+SOURCES['audit']+'">OWASP WSTG</a>, <a href="'+SOURCES['browser']+'">MDN CSP</a>, <a href="'+SOURCES['cookie']+'">MDN cookies</a>. Aucun verdict d’exploitation automatique.</p><div class="filters panel"><label>Rechercher un contrôle <input type="search" id="control-search"></label>'
    for field,label in [('domain','Domaine'),('state','État')]:
        text+='<label>'+label+' <select id="control-'+field+'"><option value="">Tous</option>'+''.join('<option value="'+e(v)+'">'+e(v)+'</option>' for v in sorted({c[field] for c in a['controls']}))+'</select></label>'
    text+='<p id="control-count" aria-live="polite"></p></div><div class="table"><table><thead><tr><th>ID et contrôle</th><th>Domaine</th><th>État</th><th>Preuve et action</th></tr></thead><tbody>'
    for c in a['controls']:
        text+='<tr class="control-row" id="'+c['id']+'" data-domain="'+e(c['domain'])+'" data-state="'+e(c['state'])+'"><td><a href="#'+c['id']+'">'+c['id']+'</a> — '+e(c['title'])+'</td><td>'+e(c['domain'])+'</td><td>'+e(c['state'])+'</td><td><details><summary>Mesure et interprétation</summary><p>'+e(c['evidence'])+'</p><p>URL : '+e(c['url'])+'</p><p>Index des mesures : '+e(', '.join(c.get('evidence_ids',[])) or 'non disponible')+'</p><p>'+e(c['method'])+'</p></details><p>'+e(c['action'])+'</p><a href="'+e(c['source'])+'" rel="noopener noreferrer">Référence technique</a></td></tr>'
    text+='</tbody></table></div></div><div id="evidence-index"><h3>Index des preuves</h3>'+grid(['ID','URL sans query','Horodatage UTC','État','Empreinte SHA-256'],[[q['id'],q['url'],str(q['at_utc'])+(' — fin de collecte TLS' if q['id'].startswith('T') else ''),q['status'],q['sha256'] or 'non disponible'] for q in a['evidence_index']])+'</div></div>'
    text+='<p><a href="controls.csv" download>'+str(control_total)+' contrôles en CSV</a> · <a href="intelligence.json" download>Analyse en JSON</a> · <a href="improvements.html">Catalogue des 100 améliorations</a></p></section>'
    return text


def intelligence_assets():
    return '''<style>
html{scroll-behavior:smooth}svg{max-width:100%;height:auto}.decision-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,290px),1fr));gap:12px}.decision-grid .panel{margin:0}.control-row td{white-space:normal}body.direction #perimetre,body.direction #couverture,body.direction #constats,body.direction #inventaire,body.direction #annexes,body.direction #evolutions,body.direction .technical-detail{display:none}#plan-dirty{padding:12px;background:#fff0c5;border:1px solid #aa7500;color:#553b00}input:focus,select:focus,button:focus,a:focus{outline:3px solid #1477b5;outline-offset:2px}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}@media print{.audience-switch,.filters,#plan-dirty{display:none!important}details>*{display:block!important}.technical-detail{display:block!important}body.direction section{display:block!important}.control-row[hidden]{display:table-row!important}.finding[hidden]{display:block!important}}
#control-matrix td:nth-child(3){white-space:nowrap;min-width:100px}#control-matrix th:first-child{width:24%}#control-matrix th:nth-child(2){width:13%}#control-matrix th:nth-child(3){width:12%}#evidence-index td:first-child,#evidence-index th:first-child{white-space:nowrap;min-width:72px}
</style><script>
const controls=Array.from(document.querySelectorAll('.control-row'));
function filterControls(){const q=document.getElementById('control-search').value.toLocaleLowerCase();const d=document.getElementById('control-domain').value;const s=document.getElementById('control-state').value;let n=0;controls.forEach(row=>{row.hidden=Boolean((d&&row.dataset.domain!==d)||(s&&row.dataset.state!==s)||!row.textContent.toLocaleLowerCase().includes(q));if(!row.hidden)n++;});document.getElementById('control-count').textContent=n+' / '+controls.length+' contrôles affichés';}
for(const id of ['control-search','control-domain','control-state'])document.getElementById(id).addEventListener('input',filterControls);filterControls();
document.getElementById('audience').addEventListener('change',event=>{document.body.classList.toggle('direction',event.target.value==='direction');});
const dirty=document.createElement('p');dirty.id='plan-dirty';dirty.role='status';dirty.hidden=true;dirty.textContent='Plan modifié dans ce navigateur : exportez le JSON pour conserver les changements.';document.getElementById('export-plan').after(dirty);
document.querySelectorAll('.plan-row input').forEach(input=>input.addEventListener('input',()=>{dirty.hidden=false;}));document.getElementById('export-plan').addEventListener('click',()=>{dirty.hidden=true;});
document.addEventListener('keydown',event=>{if(event.key==='/'&&!event.ctrlKey&&!event.metaKey&&!event.altKey&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)){event.preventDefault();const field=document.getElementById('risk-search');document.getElementById('audience').value='full';document.body.classList.remove('direction');field.focus();}});
</script>'''


def catalogue_html():
    text='<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hackscan — catalogue des contrôles</title>'+styles()+'</head><body><main><header><div class="tag">Hackscan · catalogue fonctionnel</div><h1>100 améliorations intégrées</h1><p>60 règles passives · 20 fonctions d’analyse · 20 fonctions de rapport</p></header><div class="page-actions"><a class="action primary" href="report.html">Rapport technique</a><a class="action" href="report.html#direction-report">Rapport direction</a><a class="action" href="report.pdf" download>Rapport PDF</a><a class="action" href="improvements.json" download>Catalogue JSON</a></div><div class="panel"><p>Une fonctionnalité implémentée peut produire un état inconnu si aucune preuve n’a été collectée. Ces règles ne constituent pas 100 tests d’exploitation.</p></div>'
    text+=grid(['ID','Amélioration','Type','Disponibilité'],[[c['id'],c['title'],c['category'],'implémentée'] for c in CATALOGUE])
    return text+'<footer>Version 5 · <a href="report.html">Retour au rapport</a></footer></main></body></html>'


def additional_exports(report, output, csv_safe):
    a=report['intelligence']
    stream=io.StringIO(newline='')
    fields=['id','title','domain','state','url','evidence','action','source','exploitation','evidence_ids']
    writer=csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore')
    writer.writeheader()
    writer.writerows({k:csv_safe(c.get(k,'')) for k in fields} for c in a['controls'])
    for name,content in [('controls.csv','\ufeff'+stream.getvalue()),
                         ('intelligence.json',json.dumps(a,ensure_ascii=False,indent=2)),
                         ('improvements.json',json.dumps(CATALOGUE,ensure_ascii=False,indent=2)),
                         ('improvements.html',catalogue_html())]:
        path=Path(output)/name
        path.write_text(content,encoding='utf-8')
        path.chmod(0o600)


def pdf_analysis(report, heading, rows, story, paragraph):
    a=report['intelligence']
    heading('8. Analyse explicable et décisions')
    story.append(paragraph(a['engine']+'. '+a['assurance']))
    rows(['État du contrôle','Nombre'],list(a['control_counts'].items()))
    rows(['Décision proposée','Justification','Responsable / action'],[[d['title'],d['reason'],d['owner']+' — '+d['action']] for d in a['decisions']])
    rows(['Cause / constats','Fenêtre','Prérequis et recontrôle'],[[g['theme']+' / '+', '.join(g['finding_ids']+g['control_ids']),g['window'],g['validation']+' / '+g['closure']] for g in a['roadmap']])
    story.append(paragraph('Âge des mesures : '+str(a['evidence_age_days'])+' jours ; métadonnées de contexte à valider.'))
    for gap in a['gaps']+a['contradictions']:
        story.append(paragraph('Limite : '+gap))
    rows(['Preuve interne attendue','Responsable proposé'],[[x['proof'],x['owner']] for x in a['internal_evidence']])
    heading('9. Les '+str(len(a['controls']))+' contrôles du profil')
    story.append(paragraph('Observé : mesure disponible sans indice relevé par cette règle ; à revoir : qualification nécessaire ; inconnu : preuve manquante. Aucun verdict d’exploitation. Le CSV et le HTML contiennent les sources et les URL de chaque contrôle.'))
    rows(['ID / domaine','Contrôle et état','Mesure / recommandation'],[[c['id']+' / '+c['domain'],c['title']+' — '+c['state'],c['evidence']+'\n'+c['action']] for c in a['controls']])
    story.append(paragraph('Catalogue des 100 ajouts : improvements.html / improvements.json. Analyse versionnée : intelligence.json. Sources : '+ ' ; '.join(SOURCES.values())))
