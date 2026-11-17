import os, sqlite3, secrets, datetime, hmac, time, json
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, abort

app=Flask(__name__)
app.secret_key=os.environ.get('SECRET_KEY',secrets.token_hex(32))
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','1')=='1',MAX_CONTENT_LENGTH=30000)
DB=os.environ.get('DATABASE_PATH','/data/zerofit.sqlite3')
ADMIN_PASSWORD=os.environ.get('ADMIN_PASSWORD','')
FIELDS=['model','expiry','price','discount','card','cardType','support','monthly','months','extra','cardTerms','terms','verified']
MODES=('general','subscription')
PRESETS={750000:(33000,150),1500000:(66000,150),2250000:(99000,150),3000000:(132000,150)}
DEFAULT_TERMS='150개월 납입. 만기 환급은 계약 약관의 요건 충족 시에만 가능하며 중도 해지 시 손실이 발생할 수 있습니다. 월 납입금은 별도 부담입니다.'

def db():
    os.makedirs(os.path.dirname(os.path.abspath(DB)),exist_ok=True)
    c=sqlite3.connect(DB,timeout=10)
    c.row_factory=sqlite3.Row
    c.execute('CREATE TABLE IF NOT EXISTS quotes (id INTEGER PRIMARY KEY, token TEXT UNIQUE NOT NULL, model TEXT NOT NULL, expiry TEXT NOT NULL, price INTEGER NOT NULL, discount INTEGER NOT NULL, card INTEGER NOT NULL, cardType TEXT NOT NULL, support INTEGER NOT NULL, monthly INTEGER NOT NULL, months INTEGER NOT NULL, extra INTEGER NOT NULL, cardTerms TEXT NOT NULL, terms TEXT NOT NULL, verified INTEGER NOT NULL, created TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)')
    cols={r[1] for r in c.execute('PRAGMA table_info(quotes)')}
    for col,typ in [('purchase_mode',"TEXT NOT NULL DEFAULT 'general'"),('cards_json',"TEXT NOT NULL DEFAULT '[]'"),('freeds_json',"TEXT NOT NULL DEFAULT '[]'"),('subscription_json',"TEXT NOT NULL DEFAULT '{}'"),('compare_enabled',"INTEGER NOT NULL DEFAULT 0")]:
        if col not in cols: c.execute(f'ALTER TABLE quotes ADD COLUMN {col} {typ}')
    c.commit()
    return c

def login_required(fn):
    @wraps(fn)
    def wrapper(*a,**kw):
        if not session.get('admin'): return jsonify(error='로그인이 필요합니다.'),401
        return fn(*a,**kw)
    return wrapper

def csrf():
    if not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),session.get('csrf','invalid')): abort(403)

def validate(raw):
    if not isinstance(raw,dict): raise ValueError('잘못된 입력입니다.')
    def integer(v,name,limit=100_000_000_000):
        if isinstance(v,bool) or not str(v).isdigit(): raise ValueError(f'{name}: 0 이상의 정수를 입력하세요.')
        n=int(v)
        if n>limit: raise ValueError(f'{name}: 입력 범위를 확인하세요.')
        return n
    d={}
    for k in ['price','discount','extra']: d[k]=integer(raw.get(k,0),k)
    if d['price']<=0: raise ValueError('판매가를 입력하세요.')
    d['purchase_mode']=str(raw.get('purchase_mode','general'))
    if d['purchase_mode'] not in MODES: raise ValueError('구매 방식을 선택하세요.')
    cards=raw.get('cards',[])
    if not isinstance(cards,list) or len(cards)>3: raise ValueError('카드 혜택은 최대 3개입니다.')
    checked=[]
    for i,c in enumerate(cards):
        if not isinstance(c,dict): raise ValueError('카드 입력 형식을 확인하세요.')
        checked.append({'name':str(c.get('name','')).strip()[:80], 'amount':integer(c.get('amount',0),'카드 혜택'), 'type':str(c.get('type','조건부/추후 지급'))[:60], 'terms':str(c.get('terms','')).strip()[:1200]})
    freeds=raw.get('freeds',[])
    if not isinstance(freeds,list) or len(freeds)>6: raise ValueError('하이프리드는 최대 6개입니다.')
    fs=[]
    for f in freeds:
        if not isinstance(f,dict): raise ValueError('하이프리드 입력 형식을 확인하세요.')
        support=integer(f.get('support',0),'지원금')
        monthly=integer(f.get('monthly',0),'월 납입금')
        months=integer(f.get('months',0),'납입 개월 수',600)
        if support and (not monthly or not months): raise ValueError('하이프리드 월 납입금과 기간을 입력하세요.')
        fs.append({'support':support,'monthly':monthly,'months':months,'terms':str(f.get('terms','')).strip()[:1200]})
    d['compare_enabled']=int(raw.get('compare_enabled') is True)
    sub=raw.get('subscription',{})
    if not isinstance(sub,dict): raise ValueError('구독 입력 형식을 확인하세요.')
    sub={'monthly':integer(sub.get('monthly',0),'구독 월 이용료'),'months':integer(sub.get('months',0),'구독 개월 수',600),'initial':integer(sub.get('initial',0),'구독 초기 비용'),'terms':str(sub.get('terms','')).strip()[:2000]}
    if (d['purchase_mode']=='subscription' or d['compare_enabled']) and (sub['monthly']==0 or sub['months']==0): raise ValueError('구독 구매는 월 이용료와 구독 기간이 필요합니다.')
    if d['purchase_mode']=='general' and not d['compare_enabled'] and (sub['monthly'] or sub['initial']): raise ValueError('일반 구매에 구독 금액을 입력할 수 없습니다.')
    total_card=sum(x['amount'] for x in checked)
    total_support=sum(x['support'] for x in fs)
    if d['discount']+total_card+total_support>d['price']: raise ValueError('할인·카드·하이프리드 지원금 합계가 판매가를 초과합니다.')
    d['cards_json']=json.dumps(checked,ensure_ascii=False)
    d['freeds_json']=json.dumps(fs,ensure_ascii=False)
    d['subscription_json']=json.dumps(sub,ensure_ascii=False)
    d.update(card=total_card,support=total_support,monthly=sum(x['monthly'] for x in fs),months=0,cardType='복수 혜택',cardTerms='\n'.join(x['terms'] for x in checked),terms=str(raw.get('terms','')).strip()[:3000] or DEFAULT_TERMS)
    for k,maxlen in [('model',120)]: d[k]=str(raw.get(k,'')).strip()[:maxlen]
    if not d['model']: raise ValueError('제품명을 입력하세요.')
    d['verified']=int(raw.get('verified') is True)
    try: expiry=datetime.date.fromisoformat(str(raw.get('expiry','')))
    except ValueError: raise ValueError('유효기간을 입력하세요.')
    d['expiry']=expiry.isoformat()
    return d

def public_quote(row):
    d={k:row[k] for k in FIELDS}
    d['purchase_mode']=row['purchase_mode']
    d['compare_enabled']=bool(row['compare_enabled'])
    cards=json.loads(row['cards_json'])
    freeds=json.loads(row['freeds_json'])
    subscription=json.loads(row['subscription_json'])
    # 기존 v3 저장 견적을 자동 호환
    if not cards and row['card']: cards=[{'name':'기존 카드 혜택','amount':row['card'],'type':row['cardType'],'terms':row['cardTerms']}]
    if not freeds and row['support']: freeds=[{'support':row['support'],'monthly':row['monthly'],'months':row['months'],'terms':''}]
    d.update(cards=cards,freeds=freeds,subscription=subscription)
    d['result']=d['price']-d['discount']-sum(x['amount'] for x in cards)-sum(x['support'] for x in freeds)
    d['total']=sum(x['monthly']*x['months'] for x in freeds)
    d['subscription_total']=subscription.get('monthly',0)*subscription.get('months',0)+subscription.get('initial',0)
    d['general_upfront']=max(0,d['result'])+d['extra']
    d['general_commitment']=d['general_upfront']+d['total']
    d['subscription_commitment']=d['subscription_total']+d['total']+d['extra']
    d['expired']=d['expiry']<datetime.date.today().isoformat()
    return d

@app.after_request
def headers(resp):
    resp.headers['X-Content-Type-Options']='nosniff'
    resp.headers['Referrer-Policy']='no-referrer'
    resp.headers['X-Frame-Options']='DENY'
    resp.headers['Cache-Control']='no-store'
    resp.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    return resp

@app.get('/')
def home(): return render_template('index.html',mode='admin')

@app.get('/q/<token>')
def view(token):
    if len(token)>80: abort(404)
    with db() as c: row=c.execute('SELECT * FROM quotes WHERE token=? AND revoked=0',(token,)).fetchone()
    if not row: abort(404)
    return render_template('index.html',mode='viewer',quote=public_quote(row))

@app.get('/api/status')
def status():
    return jsonify(logged_in=bool(session.get('admin')),csrf=session.get('csrf','') if session.get('admin') else '')

@app.post('/api/login')
def login():
    data=request.get_json(silent=True) or {}
    if not ADMIN_PASSWORD: return jsonify(error='서버 ADMIN_PASSWORD 설정이 필요합니다.'),503
    if not hmac.compare_digest(str(data.get('password','')),ADMIN_PASSWORD):
        time.sleep(.4)
        return jsonify(error='비밀번호가 일치하지 않습니다.'),401
    session.clear();session['admin']=True;session['csrf']=secrets.token_urlsafe(32)
    return jsonify(ok=True,csrf=session['csrf'])

@app.post('/api/logout')
@login_required
def logout(): csrf();session.clear();return jsonify(ok=True)

@app.get('/api/quotes')
@login_required
def quotes():
    with db() as c: rows=c.execute('SELECT * FROM quotes ORDER BY id DESC LIMIT 500').fetchall()
    return jsonify(quotes=[dict(public_quote(r),id=r['id'],token=r['token'],revoked=bool(r['revoked'])) for r in rows])

@app.post('/api/quotes')
@login_required
def create():
    csrf()
    try: d=validate(request.get_json(silent=True))
    except ValueError as e: return jsonify(error=str(e)),400
    token=secrets.token_urlsafe(24)
    cols=['token']+FIELDS+['purchase_mode','cards_json','freeds_json','subscription_json','compare_enabled','created']
    vals=[token]+[d[k] for k in FIELDS]+[d[k] for k in ['purchase_mode','cards_json','freeds_json','subscription_json']]+[datetime.datetime.now(datetime.timezone.utc).isoformat()]
    with db() as c:
        cur=c.execute(f"INSERT INTO quotes ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})",vals)
        qid=cur.lastrowid
    return jsonify(id=qid,url=request.host_url.rstrip('/')+'/q/'+token),201

@app.put('/api/quotes/<int:qid>')
@login_required
def update(qid):
    csrf()
    try: d=validate(request.get_json(silent=True))
    except ValueError as e: return jsonify(error=str(e)),400
    with db() as c:
        result=c.execute('UPDATE quotes SET '+','.join(k+'=?' for k in FIELDS+['purchase_mode','cards_json','freeds_json','subscription_json','compare_enabled'])+' WHERE id=? AND revoked=0',[d[k] for k in FIELDS+['purchase_mode','cards_json','freeds_json','subscription_json']]+[qid])
        if not result.rowcount: abort(404)
    return jsonify(ok=True)

@app.delete('/api/quotes/<int:qid>')
@login_required
def revoke(qid):
    csrf()
    with db() as c:
        result=c.execute('UPDATE quotes SET revoked=1 WHERE id=?',(qid,))
        if not result.rowcount: abort(404)
    return jsonify(ok=True)

@app.get('/health')
def health(): return jsonify(ok=True)

if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT','8000')),debug=False)
