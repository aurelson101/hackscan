"""Conseiller RSSI facultatif : faits expurgés, JSON validé, aucune action."""
import hashlib
import json
import os
import re

import requests

SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'properties': {
        'summary': {'type': 'string'},
        'priorities': {'type': 'array', 'items': {'type': 'string'}, 'maxItems': 5},
        'questions': {'type': 'array', 'items': {'type': 'string'}, 'maxItems': 5},
    },
    'required': ['summary', 'priorities', 'questions'],
}


def _prompt(report):
    facts = [{'title': f.get('title'), 'severity': f.get('severity'), 'confidence': f.get('confidence'),
              'remediation': f.get('remediation')} for f in report.get('findings', [])[:30]]
    return ('Tu es conseiller RSSI. Réponds uniquement en JSON avec summary (chaine), priorities (liste max 5), '
            'questions (liste max 5). N’invente aucune CVE, aucun exploit, aucun fait. Chaque proposition exige validation humaine. '
            'Données expurgées : ' + json.dumps({'status': report.get('status'), 'findings': facts,
            'limitation_count': len(report.get('limitations', []))}, ensure_ascii=False))


def _validated(raw):
    if not isinstance(raw, dict) or re.search(r'\bCVE-\d{4}-\d{4,}\b', json.dumps(raw), re.I):
        raise ValueError('Réponse IA invalide ou CVE non fournie')
    summary, priorities, questions = raw.get('summary'), raw.get('priorities'), raw.get('questions')
    if not isinstance(summary, str) or not isinstance(priorities, list) or not isinstance(questions, list):
        raise ValueError('Schéma IA invalide')
    return {'summary': summary[:3000], 'priorities': [str(x)[:500] for x in priorities[:5]],
            'questions': [str(x)[:500] for x in questions[:5]]}


def _openai_text(response):
    data = response.json()
    if isinstance(data.get('output_text'), str):
        return data['output_text']
    for item in data.get('output', []):
        if item.get('type') == 'message':
            for content in item.get('content', []):
                if content.get('type') == 'output_text':
                    return content.get('text', '')
    raise ValueError('Réponse OpenAI sans contenu JSON')


def ai_advice(report, provider='none', model=None, timeout=45):
    if provider == 'none':
        return {'status': 'désactivé', 'policy': 'IA facultative ; aucune donnée transmise.'}
    defaults = {'ollama': 'metatron-qwen', 'openai': 'gpt-5.6-terra', 'mistral': 'mistral-small-2603'}
    if provider not in defaults:
        raise ValueError('Fournisseur IA inconnu')
    model, prompt = model or defaults[provider], _prompt(report)
    session = requests.Session()
    session.trust_env = False
    try:
        if provider == 'ollama':
            response = session.post('http://127.0.0.1:11434/api/generate',
                json={'model': model, 'prompt': prompt, 'stream': False, 'format': 'json'},
                timeout=timeout, allow_redirects=False)
            response.raise_for_status()
            text = response.json().get('response', '{}')
        elif provider == 'openai':
            key = os.environ.get('OPENAI_API_KEY')
            if not key:
                raise ValueError('OPENAI_API_KEY absente')
            response = session.post('https://api.openai.com/v1/responses',
                headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}, timeout=timeout,
                allow_redirects=False, json={'model': model, 'input': prompt,
                    'text': {'format': {'type': 'json_schema', 'name': 'rssi_advice', 'strict': True, 'schema': SCHEMA}}})
            response.raise_for_status()
            text = _openai_text(response)
        else:
            key = os.environ.get('MISTRAL_API_KEY')
            if not key:
                raise ValueError('MISTRAL_API_KEY absente')
            response = session.post('https://api.mistral.ai/v1/chat/completions',
                headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}, timeout=timeout,
                allow_redirects=False, json={'model': model, 'messages': [
                    {'role': 'system', 'content': 'Conseiller RSSI défensif.'}, {'role': 'user', 'content': prompt}],
                    'response_format': {'type': 'json_object'}, 'safe_prompt': True})
            response.raise_for_status()
            text = response.json()['choices'][0]['message']['content']
        if not isinstance(text, str) or len(text.encode('utf-8')) > 1024 * 1024:
            raise ValueError('Réponse IA invalide ou trop volumineuse')
        result = _validated(json.loads(text))
        return {'status': 'proposition à valider', 'provider': provider, 'model': model,
                'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(), 'result': result,
                'policy': 'Données expurgées ; validation humaine ; aucune exécution ni décision automatique.'}
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        return {'status': 'indisponible', 'detail': str(exc), 'provider': provider, 'model': model,
                'policy': 'Aucun repli automatique vers un autre fournisseur.'}


def local_advice(report, model='metatron-qwen', timeout=45):
    return ai_advice(report, 'ollama', model, timeout)
