import sqlite3, os, json, hashlib, random, string
from datetime import datetime, timedelta, date
from functools import wraps
from flask import Flask, request, jsonify, g
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'marinaone_secret_2024'
DB_PATH = os.path.join(os.path.dirname(__file__), 'marina.db')

# ─────────────────────────── DB helpers ───────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur

def row_to_dict(row):
    if row is None: return None
    return dict(row)

def rows_to_list(rows):
    return [dict(r) for r in rows]

# ─────────────────────────── CORS ───────────────────────────
@app.after_request
def add_cors(r):
    r.headers['Access-Control-Allow-Origin'] = '*'
    r.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    r.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    return r

@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options(_=None, path=None):
    return jsonify({}), 200

# ─────────────────────────── JWT Auth ───────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token ausente'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except Exception:
            return jsonify({'error': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/auth/login', methods=['POST'])
def login():
    d = request.get_json()
    email = d.get('email', '').lower()
    password = d.get('password', '')
    user = row_to_dict(query('SELECT * FROM users WHERE email=?', [email], one=True))
    if not user:
        return jsonify({'error': 'Credenciais inválidas'}), 401
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if user['password_hash'] != pw_hash:
        return jsonify({'error': 'Credenciais inválidas'}), 401
    token = jwt.encode({
        'user_id': user['id'],
        'email': user['email'],
        'name': user['name'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=12)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token, 'user': {'id': user['id'], 'name': user['name'], 'email': user['email'], 'role': user['role']}})

@app.route('/api/auth/me', methods=['GET'])
@token_required
def me():
    return jsonify(g.current_user)

# ─────────────────────────── CLIENTES ───────────────────────────
@app.route('/api/clients', methods=['GET'])
@token_required
def get_clients():
    search = request.args.get('search', '')
    tier = request.args.get('tier', '')
    sql = 'SELECT c.*, (SELECT COUNT(*) FROM vessels WHERE client_id=c.id AND active=1) as vessel_count FROM clients c WHERE c.active=1'
    args = []
    if search:
        sql += ' AND (c.name LIKE ? OR c.email LIKE ? OR c.cpf LIKE ?)'
        args += [f'%{search}%', f'%{search}%', f'%{search}%']
    if tier:
        sql += ' AND c.tier=?'
        args.append(tier)
    sql += ' ORDER BY c.name'
    return jsonify(rows_to_list(query(sql, args)))

@app.route('/api/clients/<int:cid>', methods=['GET'])
@token_required
def get_client(cid):
    c = row_to_dict(query('SELECT * FROM clients WHERE id=?', [cid], one=True))
    if not c: return jsonify({'error': 'Não encontrado'}), 404
    c['vessels'] = rows_to_list(query('SELECT * FROM vessels WHERE client_id=? AND active=1', [cid]))
    c['contracts'] = rows_to_list(query('SELECT ct.*, s.number as spot_number FROM contracts ct LEFT JOIN spots s ON ct.spot_id=s.id WHERE ct.client_id=?', [cid]))
    c['charges'] = rows_to_list(query('SELECT * FROM financial_charges WHERE client_id=? ORDER BY due_date DESC LIMIT 10', [cid]))
    return jsonify(c)

@app.route('/api/clients', methods=['POST'])
@token_required
def create_client():
    d = request.get_json()
    cur = execute('''INSERT INTO clients (name,email,phone,cpf,tier,address,notes)
                     VALUES (?,?,?,?,?,?,?)''',
                  [d['name'], d.get('email'), d.get('phone'), d.get('cpf'),
                   d.get('tier','standard'), d.get('address'), d.get('notes')])
    _gen_alert('sistema', f'Novo cliente cadastrado: {d["name"]}', 'info')
    return jsonify({'id': cur.lastrowid}), 201

@app.route('/api/clients/<int:cid>', methods=['PUT'])
@token_required
def update_client(cid):
    d = request.get_json()
    execute('''UPDATE clients SET name=?,email=?,phone=?,cpf=?,tier=?,address=?,notes=?
               WHERE id=?''',
            [d['name'], d.get('email'), d.get('phone'), d.get('cpf'),
             d.get('tier','standard'), d.get('address'), d.get('notes'), cid])
    _recalc_ltv(cid)
    return jsonify({'ok': True})

@app.route('/api/clients/<int:cid>', methods=['DELETE'])
@token_required
def delete_client(cid):
    execute('UPDATE clients SET active=0 WHERE id=?', [cid])
    return jsonify({'ok': True})

def _recalc_ltv(client_id):
    r = row_to_dict(query('SELECT COALESCE(SUM(amount),0) as total FROM financial_charges WHERE client_id=? AND status="paid"', [client_id], one=True))
    execute('UPDATE clients SET ltv=? WHERE id=?', [r['total'], client_id])

# ─────────────────────────── EMBARCAÇÕES ───────────────────────────
@app.route('/api/vessels', methods=['GET'])
@token_required
def get_vessels():
    search = request.args.get('search', '')
    client_id = request.args.get('client_id', '')
    sql = '''SELECT v.*, c.name as client_name, c.tier as client_tier,
             s.number as spot_number, s.type as spot_type
             FROM vessels v
             JOIN clients c ON v.client_id=c.id
             LEFT JOIN contracts ct ON ct.vessel_id=v.id AND ct.status="active"
             LEFT JOIN spots s ON ct.spot_id=s.id
             WHERE v.active=1'''
    args = []
    if search:
        sql += ' AND (v.name LIKE ? OR v.registration LIKE ? OR c.name LIKE ?)'
        args += [f'%{search}%', f'%{search}%', f'%{search}%']
    if client_id:
        sql += ' AND v.client_id=?'
        args.append(client_id)
    sql += ' ORDER BY v.name'
    return jsonify(rows_to_list(query(sql, args)))

@app.route('/api/vessels/<int:vid>', methods=['GET'])
@token_required
def get_vessel(vid):
    v = row_to_dict(query('''SELECT v.*, c.name as client_name FROM vessels v
                              JOIN clients c ON v.client_id=c.id WHERE v.id=?''', [vid], one=True))
    if not v: return jsonify({'error': 'Não encontrado'}), 404
    v['history'] = rows_to_list(query('SELECT * FROM queue_operations WHERE vessel_id=? ORDER BY requested_at DESC LIMIT 20', [vid]))
    v['maintenance'] = rows_to_list(query('SELECT * FROM maintenance_os WHERE vessel_id=? ORDER BY created_at DESC LIMIT 10', [vid]))
    v['contract'] = row_to_dict(query('SELECT ct.*, s.number as spot_number FROM contracts ct LEFT JOIN spots s ON ct.spot_id=s.id WHERE ct.vessel_id=? AND ct.status="active"', [vid], one=True))
    return jsonify(v)

@app.route('/api/vessels', methods=['POST'])
@token_required
def create_vessel():
    d = request.get_json()
    cur = execute('''INSERT INTO vessels (client_id,name,type,length,beam,draft,year,registration,model,manufacturer,engine,notes)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                  [d['client_id'], d['name'], d.get('type'), d.get('length'), d.get('beam'),
                   d.get('draft'), d.get('year'), d.get('registration'), d.get('model'),
                   d.get('manufacturer'), d.get('engine'), d.get('notes')])
    return jsonify({'id': cur.lastrowid}), 201

@app.route('/api/vessels/<int:vid>', methods=['PUT'])
@token_required
def update_vessel(vid):
    d = request.get_json()
    execute('''UPDATE vessels SET name=?,type=?,length=?,beam=?,draft=?,year=?,registration=?,
               model=?,manufacturer=?,engine=?,notes=? WHERE id=?''',
            [d['name'], d.get('type'), d.get('length'), d.get('beam'), d.get('draft'),
             d.get('year'), d.get('registration'), d.get('model'), d.get('manufacturer'),
             d.get('engine'), d.get('notes'), vid])
    return jsonify({'ok': True})

@app.route('/api/vessels/<int:vid>', methods=['DELETE'])
@token_required
def delete_vessel(vid):
    execute('UPDATE vessels SET active=0 WHERE id=?', [vid])
    return jsonify({'ok': True})

# ─────────────────────────── VAGAS ───────────────────────────
@app.route('/api/spots', methods=['GET'])
@token_required
def get_spots():
    spot_type = request.args.get('type', '')
    status = request.args.get('status', '')
    sql = '''SELECT s.*, v.name as vessel_name, c.name as client_name
             FROM spots s
             LEFT JOIN vessels v ON s.vessel_id=v.id
             LEFT JOIN clients c ON v.client_id=c.id
             WHERE 1=1'''
    args = []
    if spot_type:
        sql += ' AND s.type=?'; args.append(spot_type)
    if status:
        sql += ' AND s.status=?'; args.append(status)
    sql += ' ORDER BY s.number'
    return jsonify(rows_to_list(query(sql, args)))

@app.route('/api/spots/summary', methods=['GET'])
@token_required
def spots_summary():
    rows = rows_to_list(query('''SELECT type, status, COUNT(*) as count FROM spots GROUP BY type, status'''))
    result = {'seca': {'total': 0, 'available': 0, 'occupied': 0, 'maintenance': 0},
              'molhada': {'total': 0, 'available': 0, 'occupied': 0, 'maintenance': 0}}
    for r in rows:
        t = r['type']; s = r['status']
        result[t]['total'] += r['count']
        if s in result[t]: result[t][s] += r['count']
    return jsonify(result)

@app.route('/api/spots/<int:sid>', methods=['PUT'])
@token_required
def update_spot(sid):
    d = request.get_json()
    execute('UPDATE spots SET status=?, vessel_id=? WHERE id=?',
            [d.get('status'), d.get('vessel_id'), sid])
    return jsonify({'ok': True})

# ─────────────────────────── CONTRATOS ───────────────────────────
@app.route('/api/contracts', methods=['GET'])
@token_required
def get_contracts():
    status = request.args.get('status', '')
    sql = '''SELECT ct.*, c.name as client_name, c.tier as client_tier,
             v.name as vessel_name, s.number as spot_number
             FROM contracts ct
             JOIN clients c ON ct.client_id=c.id
             JOIN vessels v ON ct.vessel_id=v.id
             LEFT JOIN spots s ON ct.spot_id=s.id
             WHERE 1=1'''
    args = []
    if status:
        sql += ' AND ct.status=?'; args.append(status)
    sql += ' ORDER BY ct.start_date DESC'
    return jsonify(rows_to_list(query(sql, args)))

@app.route('/api/contracts', methods=['POST'])
@token_required
def create_contract():
    d = request.get_json()
    cur = execute('''INSERT INTO contracts (client_id,vessel_id,spot_id,type,start_date,end_date,monthly_value,status,notes)
                     VALUES (?,?,?,?,?,?,?,?,?)''',
                  [d['client_id'], d['vessel_id'], d.get('spot_id'), d['type'],
                   d['start_date'], d.get('end_date'), d['monthly_value'],
                   d.get('status','active'), d.get('notes')])
    if d.get('spot_id'):
        execute('UPDATE spots SET status="occupied", vessel_id=? WHERE id=?',
                [d['vessel_id'], d['spot_id']])
    _generate_monthly_charges(cur.lastrowid)
    return jsonify({'id': cur.lastrowid}), 201

@app.route('/api/contracts/<int:cid>', methods=['PUT'])
@token_required
def update_contract(cid):
    d = request.get_json()
    old = row_to_dict(query('SELECT * FROM contracts WHERE id=?', [cid], one=True))
    execute('''UPDATE contracts SET status=?,monthly_value=?,end_date=?,notes=? WHERE id=?''',
            [d.get('status', old['status']), d.get('monthly_value', old['monthly_value']),
             d.get('end_date', old['end_date']), d.get('notes', old['notes']), cid])
    if d.get('status') == 'cancelled' and old.get('spot_id'):
        execute('UPDATE spots SET status="available", vessel_id=NULL WHERE id=?', [old['spot_id']])
    return jsonify({'ok': True})

def _generate_monthly_charges(contract_id):
    ct = row_to_dict(query('SELECT * FROM contracts WHERE id=?', [contract_id], one=True))
    if not ct: return
    start = datetime.strptime(ct['start_date'], '%Y-%m-%d')
    for i in range(3):
        due = (start + timedelta(days=30*i)).strftime('%Y-%m-%d')
        execute('''INSERT INTO financial_charges (client_id,contract_id,description,amount,due_date,status)
                   VALUES (?,?,?,?,?,?)''',
                [ct['client_id'], contract_id,
                 f'Mensalidade armazenagem {ct["type"]} - {(start+timedelta(days=30*i)).strftime("%m/%Y")}',
                 ct['monthly_value'], due, 'pending'])

# ─────────────────────────── FILA DE OPERAÇÕES ───────────────────────────
@app.route('/api/queue', methods=['GET'])
@token_required
def get_queue():
    status = request.args.get('status', '')
    sql = '''SELECT q.*, v.name as vessel_name, v.type as vessel_type,
             v.length as vessel_length, c.name as client_name, c.tier as client_tier
             FROM queue_operations q
             JOIN vessels v ON q.vessel_id=v.id
             JOIN clients c ON q.client_id=c.id
             WHERE 1=1'''
    args = []
    if status:
        statuses = status.split(',')
        placeholders = ','.join('?' * len(statuses))
        sql += f' AND q.status IN ({placeholders})'
        args += statuses
    else:
        sql += ' AND q.status NOT IN ("completed","cancelled")'
    sql += ' ORDER BY q.priority DESC, q.requested_at ASC'
    return jsonify(rows_to_list(query(sql, args)))

@app.route('/api/queue/history', methods=['GET'])
@token_required
def get_queue_history():
    rows = rows_to_list(query('''SELECT q.*, v.name as vessel_name, c.name as client_name
             FROM queue_operations q
             JOIN vessels v ON q.vessel_id=v.id
             JOIN clients c ON q.client_id=c.id
             WHERE q.status IN ("completed","cancelled")
             ORDER BY q.requested_at DESC LIMIT 50'''))
    return jsonify(rows)

@app.route('/api/queue', methods=['POST'])
@token_required
def create_queue():
    d = request.get_json()
    vessel = row_to_dict(query('SELECT * FROM vessels WHERE id=?', [d['vessel_id']], one=True))
    if not vessel: return jsonify({'error': 'Embarcação não encontrada'}), 404
    client_info = row_to_dict(query('SELECT * FROM clients WHERE id=?', [vessel['client_id']], one=True))
    priority = 1 if client_info and client_info.get('tier') in ('gold','vip') else 0
    cur = execute('''INSERT INTO queue_operations (vessel_id,client_id,operation_type,status,priority,notes)
                     VALUES (?,?,?,?,?,?)''',
                  [d['vessel_id'], vessel['client_id'], d['operation_type'], 'waiting', priority, d.get('notes')])
    return jsonify({'id': cur.lastrowid}), 201

@app.route('/api/queue/<int:qid>', methods=['PUT'])
@token_required
def update_queue(qid):
    d = request.get_json()
    old = row_to_dict(query('SELECT * FROM queue_operations WHERE id=?', [qid], one=True))
    new_status = d.get('status', old['status'])
    started_at = old['started_at']
    completed_at = old['completed_at']
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if new_status == 'in_progress' and not started_at:
        started_at = now
    if new_status in ('completed', 'cancelled') and not completed_at:
        completed_at = now
    execute('''UPDATE queue_operations SET status=?,started_at=?,completed_at=?,operator=?,notes=?
               WHERE id=?''',
            [new_status, started_at, completed_at, d.get('operator', old['operator']),
             d.get('notes', old['notes']), qid])
    return jsonify({'ok': True})

@app.route('/api/queue/<int:qid>', methods=['DELETE'])
@token_required
def delete_queue(qid):
    execute('UPDATE queue_operations SET status="cancelled" WHERE id=?', [qid])
    return jsonify({'ok': True})

# ─────────────────────────── FINANCEIRO ───────────────────────────
@app.route('/api/financial/charges', methods=['GET'])
@token_required
def get_charges():
    status = request.args.get('status', '')
    client_id = request.args.get('client_id', '')
    sql = '''SELECT fc.*, c.name as client_name, c.tier as client_tier
             FROM financial_charges fc
             JOIN clients c ON fc.client_id=c.id
             WHERE 1=1'''
    args = []
    if status:
        sql += ' AND fc.status=?'; args.append(status)
    if client_id:
        sql += ' AND fc.client_id=?'; args.append(client_id)
    sql += ' ORDER BY fc.due_date DESC'
    return jsonify(rows_to_list(query(sql, args)))

@app.route('/api/financial/charges', methods=['POST'])
@token_required
def create_charge():
    d = request.get_json()
    cur = execute('''INSERT INTO financial_charges (client_id,contract_id,description,amount,due_date,status,notes)
                     VALUES (?,?,?,?,?,?,?)''',
                  [d['client_id'], d.get('contract_id'), d['description'], d['amount'],
                   d['due_date'], d.get('status','pending'), d.get('notes')])
    return jsonify({'id': cur.lastrowid}), 201

@app.route('/api/financial/charges/<int:fid>', methods=['PUT'])
@token_required
def update_charge(fid):
    d = request.get_json()
    old = row_to_dict(query('SELECT * FROM financial_charges WHERE id=?', [fid], one=True))
    paid_date = d.get('paid_date', old['paid_date'])
    if d.get('status') == 'paid' and not paid_date:
        paid_date = datetime.now().strftime('%Y-%m-%d')
    execute('''UPDATE financial_charges SET status=?,paid_date=?,payment_method=?,notes=? WHERE id=?''',
            [d.get('status', old['status']), paid_date,
             d.get('payment_method', old['payment_method']),
             d.get('notes', old['notes']), fid])
    if d.get('status') == 'paid':
        _recalc_ltv(old['client_id'])
    _check_overdue()
    return jsonify({'ok': True})

@app.route('/api/financial/summary', methods=['GET'])
@token_required
def financial_summary():
    today = date.today().strftime('%Y-%m-%d')
    month_start = date.today().replace(day=1).strftime('%Y-%m-%d')
    total_paid_month = row_to_dict(query(
        'SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status="paid" AND paid_date>=?',
        [month_start], one=True))['v']
    total_pending = row_to_dict(query(
        'SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status="pending"',
        [], one=True))['v']
    total_overdue = row_to_dict(query(
        'SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status="overdue"',
        [], one=True))['v']
    count_overdue = row_to_dict(query(
        'SELECT COUNT(*) as v FROM financial_charges WHERE status="overdue"',
        [], one=True))['v']
    revenue_by_month = rows_to_list(query(
        '''SELECT strftime("%Y-%m", paid_date) as month, COALESCE(SUM(amount),0) as total
           FROM financial_charges WHERE status="paid" AND paid_date IS NOT NULL
           GROUP BY month ORDER BY month DESC LIMIT 6'''))
    return jsonify({
        'total_paid_month': total_paid_month,
        'total_pending': total_pending,
        'total_overdue': total_overdue,
        'count_overdue': count_overdue,
        'revenue_by_month': revenue_by_month
    })

def _check_overdue():
    today = date.today().strftime('%Y-%m-%d')
    execute("UPDATE financial_charges SET status='overdue' WHERE status='pending' AND due_date<?", [today])

# ─────────────────────────── LOJA ───────────────────────────
@app.route('/api/store/items', methods=['GET'])
@token_required
def get_store_items():
    category = request.args.get('category', '')
    low_stock = request.args.get('low_stock', '')
    sql = 'SELECT * FROM store_items WHERE active=1'
    args = []
    if category:
        sql += ' AND category=?'; args.append(category)
    if low_stock:
        sql += ' AND stock <= min_stock'
    sql += ' ORDER BY category, name'
    return jsonify(rows_to_list(query(sql, args)))

@app.route('/api/store/items', methods=['POST'])
@token_required
def create_store_item():
    d = request.get_json()
    cur = execute('''INSERT INTO store_items (name,category,price,cost,stock,min_stock,unit)
                     VALUES (?,?,?,?,?,?,?)''',
                  [d['name'], d.get('category','outros'), d['price'], d.get('cost',0),
                   d.get('stock',0), d.get('min_stock',5), d.get('unit','un')])
    return jsonify({'id': cur.lastrowid}), 201

@app.route('/api/store/items/<int:iid>', methods=['PUT'])
@token_required
def update_store_item(iid):
    d = request.get_json()
    execute('''UPDATE store_items SET name=?,category=?,price=?,cost=?,stock=?,min_stock=?,unit=?
               WHERE id=?''',
            [d['name'], d.get('category'), d['price'], d.get('cost',0),
             d.get('stock',0), d.get('min_stock',5), d.get('unit','un'), iid])
    _check_stock_alerts()
    return jsonify({'ok': True})

@app.route('/api/store/items/<int:iid>', methods=['DELETE'])
@token_required
def delete_store_item(iid):
    execute('UPDATE store_items SET active=0 WHERE id=?', [iid])
    return jsonify({'ok': True})

@app.route('/api/store/orders', methods=['GET'])
@token_required
def get_orders():
    status = request.args.get('status', '')
    sql = '''SELECT o.*, v.name as vessel_name, c.name as client_name
             FROM store_orders o
             LEFT JOIN vessels v ON o.vessel_id=v.id
             LEFT JOIN clients c ON o.client_id=c.id
             WHERE 1=1'''
    args = []
    if status:
        sql += ' AND o.status=?'; args.append(status)
    sql += ' ORDER BY o.created_at DESC LIMIT 100'
    rows = rows_to_list(query(sql, args))
    for r in rows:
        try: r['items'] = json.loads(r['items'])
        except: pass
    return jsonify(rows)

@app.route('/api/store/orders', methods=['POST'])
@token_required
def create_order():
    d = request.get_json()
    items = d.get('items', [])
    subtotal = sum(i['price'] * i['qty'] for i in items)
    discount = d.get('discount', 0)
    total = subtotal - discount
    cur = execute('''INSERT INTO store_orders (vessel_id,client_id,items,subtotal,discount,total,status,payment_method,notes)
                     VALUES (?,?,?,?,?,?,?,?,?)''',
                  [d.get('vessel_id'), d.get('client_id'), json.dumps(items),
                   subtotal, discount, total,
                   d.get('status','open'), d.get('payment_method'), d.get('notes')])
    # Decrease stock
    for item in items:
        execute('UPDATE store_items SET stock=MAX(0,stock-?) WHERE id=?',
                [item['qty'], item['item_id']])
    _check_stock_alerts()
    return jsonify({'id': cur.lastrowid, 'total': total}), 201

@app.route('/api/store/orders/<int:oid>', methods=['PUT'])
@token_required
def update_order(oid):
    d = request.get_json()
    execute('UPDATE store_orders SET status=?,payment_method=?,notes=? WHERE id=?',
            [d.get('status'), d.get('payment_method'), d.get('notes'), oid])
    return jsonify({'ok': True})

@app.route('/api/store/pix-config', methods=['GET'])
@token_required
def get_pix_config():
    cfg = row_to_dict(query('SELECT * FROM store_pix_config WHERE active=1 ORDER BY id DESC', one=True))
    return jsonify(cfg or {})

@app.route('/api/store/pix-config', methods=['POST'])
@token_required
def save_pix_config():
    d = request.get_json()
    execute('UPDATE store_pix_config SET active=0')
    execute('''INSERT INTO store_pix_config (key, key_type, merchant_name, city, active)
               VALUES (?,?,?,?,1)''',
            [d['key'], d['key_type'], d['merchant_name'], d['city']])
    return jsonify({'ok': True})

@app.route('/api/store/pix-qrcode', methods=['POST'])
@token_required
def gen_pix_qrcode():
    d = request.get_json()
    amount = float(d.get('amount', 0))
    cfg = row_to_dict(query('SELECT * FROM store_pix_config WHERE active=1 ORDER BY id DESC', one=True))
    if not cfg:
        return jsonify({'error': 'PIX não configurado'}), 400
    txid = ''.join(random.choices(string.ascii_uppercase + string.digits, k=25))
    payload = _build_pix_payload(cfg['key'], cfg['merchant_name'], cfg['city'], amount, txid)
    return jsonify({'payload': payload, 'txid': txid, 'amount': amount})

def _build_pix_payload(key, name, city, amount, txid):
    def tlv(tag, value):
        return f'{tag}{len(value):02d}{value}'
    merchant_account = tlv('00', 'BR.GOV.BCB.PIX') + tlv('01', key)
    payload = (
        tlv('00', '01') +
        tlv('26', merchant_account) +
        tlv('52', '0000') +
        tlv('53', '986') +
        tlv('54', f'{amount:.2f}') +
        tlv('58', 'BR') +
        tlv('59', name[:25]) +
        tlv('60', city[:15]) +
        tlv('62', tlv('05', txid[:25]))
    )
    payload += tlv('63', _crc16(payload + '6304'))
    return payload

def _crc16(data):
    crc = 0xFFFF
    for c in data.encode('utf-8'):
        crc ^= c << 8
        for _ in range(8):
            if crc & 0x8000: crc = (crc << 1) ^ 0x1021
            else: crc <<= 1
        crc &= 0xFFFF
    return f'{crc:04X}'

def _check_stock_alerts():
    items = rows_to_list(query('SELECT * FROM store_items WHERE active=1 AND stock <= min_stock'))
    for item in items:
        existing = query('SELECT * FROM alerts WHERE entity_type="store_item" AND entity_id=? AND read_at IS NULL', [item['id']])
        if not existing:
            _gen_alert('estoque', f'Estoque baixo: {item["name"]} ({item["stock"]} {item["unit"]})', 'warning', 'store_item', item['id'])

# ─────────────────────────── MANUTENÇÃO ───────────────────────────
@app.route('/api/maintenance', methods=['GET'])
@token_required
def get_maintenance():
    status = request.args.get('status', '')
    vessel_id = request.args.get('vessel_id', '')
    sql = '''SELECT m.*, v.name as vessel_name, c.name as client_name
             FROM maintenance_os m
             LEFT JOIN vessels v ON m.vessel_id=v.id
             LEFT JOIN clients c ON v.client_id=c.id
             WHERE 1=1'''
    args = []
    if status:
        sql += ' AND m.status=?'; args.append(status)
    if vessel_id:
        sql += ' AND m.vessel_id=?'; args.append(vessel_id)
    sql += ' ORDER BY CASE m.priority WHEN "urgent" THEN 0 WHEN "high" THEN 1 WHEN "normal" THEN 2 ELSE 3 END, m.created_at DESC'
    return jsonify(rows_to_list(query(sql, args)))

@app.route('/api/maintenance', methods=['POST'])
@token_required
def create_maintenance():
    d = request.get_json()
    os_num = f'OS-{datetime.now().strftime("%Y%m%d")}-{random.randint(100,999)}'
    cur = execute('''INSERT INTO maintenance_os (vessel_id,os_number,type,description,status,priority,
                     scheduled_date,estimated_hours,cost,technician,notes)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                  [d.get('vessel_id'), os_num, d['type'], d['description'],
                   d.get('status','open'), d.get('priority','normal'),
                   d.get('scheduled_date'), d.get('estimated_hours'),
                   d.get('cost',0), d.get('technician'), d.get('notes')])
    if d.get('priority') in ('urgent','high'):
        _gen_alert('manutencao', f'OS urgente criada: {d["description"][:50]}', 'warning')
    return jsonify({'id': cur.lastrowid, 'os_number': os_num}), 201

@app.route('/api/maintenance/<int:mid>', methods=['PUT'])
@token_required
def update_maintenance(mid):
    d = request.get_json()
    old = row_to_dict(query('SELECT * FROM maintenance_os WHERE id=?', [mid], one=True))
    completed_date = old['completed_date']
    if d.get('status') == 'completed' and not completed_date:
        completed_date = datetime.now().strftime('%Y-%m-%d')
    execute('''UPDATE maintenance_os SET status=?,priority=?,scheduled_date=?,completed_date=?,
               actual_hours=?,cost=?,technician=?,notes=? WHERE id=?''',
            [d.get('status', old['status']), d.get('priority', old['priority']),
             d.get('scheduled_date', old['scheduled_date']), completed_date,
             d.get('actual_hours', old['actual_hours']), d.get('cost', old['cost']),
             d.get('technician', old['technician']), d.get('notes', old['notes']), mid])
    return jsonify({'ok': True})

@app.route('/api/maintenance/<int:mid>', methods=['DELETE'])
@token_required
def delete_maintenance(mid):
    execute("UPDATE maintenance_os SET status='cancelled' WHERE id=?", [mid])
    return jsonify({'ok': True})

# ─────────────────────────── ALERTAS ───────────────────────────
def _gen_alert(atype, message, severity='info', entity_type=None, entity_id=None):
    execute('''INSERT INTO alerts (type,message,severity,entity_type,entity_id)
               VALUES (?,?,?,?,?)''', [atype, message, severity, entity_type, entity_id])

@app.route('/api/alerts', methods=['GET'])
@token_required
def get_alerts():
    unread_only = request.args.get('unread', '')
    sql = 'SELECT * FROM alerts WHERE 1=1'
    if unread_only:
        sql += ' AND read_at IS NULL'
    sql += ' ORDER BY created_at DESC LIMIT 50'
    return jsonify(rows_to_list(query(sql)))

@app.route('/api/alerts/<int:aid>/read', methods=['PUT'])
@token_required
def mark_alert_read(aid):
    execute('UPDATE alerts SET read_at=? WHERE id=?',
            [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), aid])
    return jsonify({'ok': True})

@app.route('/api/alerts/read-all', methods=['PUT'])
@token_required
def mark_all_read():
    execute('UPDATE alerts SET read_at=? WHERE read_at IS NULL',
            [datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    return jsonify({'ok': True})

# ─────────────────────────── ANALYTICS ───────────────────────────
@app.route('/api/analytics/kpis', methods=['GET'])
@token_required
def analytics_kpis():
    today = date.today()
    month_start = today.replace(day=1).strftime('%Y-%m-%d')
    today_str = today.strftime('%Y-%m-%d')

    # Ocupação
    total_spots = row_to_dict(query('SELECT COUNT(*) as v FROM spots', one=True))['v']
    occupied = row_to_dict(query('SELECT COUNT(*) as v FROM spots WHERE status="occupied"', one=True))['v']
    seca_total = row_to_dict(query('SELECT COUNT(*) as v FROM spots WHERE type="seca"', one=True))['v']
    seca_occ = row_to_dict(query('SELECT COUNT(*) as v FROM spots WHERE type="seca" AND status="occupied"', one=True))['v']
    molhada_total = row_to_dict(query('SELECT COUNT(*) as v FROM spots WHERE type="molhada"', one=True))['v']
    molhada_occ = row_to_dict(query('SELECT COUNT(*) as v FROM spots WHERE type="molhada" AND status="occupied"', one=True))['v']

    # Financeiro
    receita_mes = row_to_dict(query('SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status="paid" AND paid_date>=?', [month_start], one=True))['v']
    inadimplencia = row_to_dict(query('SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status="overdue"', one=True))['v']
    pendente = row_to_dict(query('SELECT COALESCE(SUM(amount),0) as v FROM financial_charges WHERE status="pending"', one=True))['v']

    # Clientes
    total_clientes = row_to_dict(query('SELECT COUNT(*) as v FROM clients WHERE active=1', one=True))['v']
    vip_count = row_to_dict(query('SELECT COUNT(*) as v FROM clients WHERE active=1 AND tier IN ("gold","vip")', one=True))['v']

    # Embarcações
    total_vessels = row_to_dict(query('SELECT COUNT(*) as v FROM vessels WHERE active=1', one=True))['v']

    # Fila hoje
    queue_today = row_to_dict(query('SELECT COUNT(*) as v FROM queue_operations WHERE DATE(requested_at)=? AND status != "cancelled"', [today_str], one=True))['v']
    queue_waiting = row_to_dict(query('SELECT COUNT(*) as v FROM queue_operations WHERE status IN ("waiting","in_progress")', one=True))['v']

    # Contratos ativos
    contratos_ativos = row_to_dict(query('SELECT COUNT(*) as v FROM contracts WHERE status="active"', one=True))['v']

    # Receita por categoria
    loja_mes = row_to_dict(query('SELECT COALESCE(SUM(total),0) as v FROM store_orders WHERE status="paid" AND DATE(created_at)>=?', [month_start], one=True))['v']

    # Manutenção
    os_abertas = row_to_dict(query('SELECT COUNT(*) as v FROM maintenance_os WHERE status IN ("open","in_progress")', one=True))['v']
    os_urgentes = row_to_dict(query('SELECT COUNT(*) as v FROM maintenance_os WHERE status IN ("open","in_progress") AND priority IN ("urgent","high")', one=True))['v']
    custo_manutencao_mes = row_to_dict(query('SELECT COALESCE(SUM(cost),0) as v FROM maintenance_os WHERE completed_date>=?', [month_start], one=True))['v']

    # SLA fila - tempo médio de atendimento
    sla = row_to_dict(query('''SELECT AVG(
        (julianday(completed_at) - julianday(requested_at)) * 24 * 60
    ) as avg_min FROM queue_operations
    WHERE status="completed" AND DATE(completed_at)>=?''', [month_start], one=True))
    sla_avg = round(sla['avg_min'], 1) if sla and sla['avg_min'] else 0

    # Alertas não lidos
    alertas_nao_lidos = row_to_dict(query('SELECT COUNT(*) as v FROM alerts WHERE read_at IS NULL', one=True))['v']

    # Ticket médio loja
    ticket = row_to_dict(query('SELECT AVG(total) as v FROM store_orders WHERE status="paid"', one=True))
    ticket_medio = round(ticket['v'], 2) if ticket and ticket['v'] else 0

    # Taxa inadimplência
    total_contratos_val = row_to_dict(query('SELECT COALESCE(SUM(monthly_value),0) as v FROM contracts WHERE status="active"', one=True))['v']
    taxa_inadimplencia = round((inadimplencia / total_contratos_val * 100) if total_contratos_val else 0, 1)

    # LTV médio
    ltv_medio = row_to_dict(query('SELECT AVG(ltv) as v FROM clients WHERE active=1', one=True))
    ltv_medio = round(ltv_medio['v'], 2) if ltv_medio and ltv_medio['v'] else 0

    # Receita por tipo de contrato
    receita_seca = row_to_dict(query('''SELECT COALESCE(SUM(fc.amount),0) as v FROM financial_charges fc
        JOIN contracts ct ON fc.contract_id=ct.id
        WHERE fc.status="paid" AND fc.paid_date>=? AND ct.type="seca"''', [month_start], one=True))['v']
    receita_molhada = row_to_dict(query('''SELECT COALESCE(SUM(fc.amount),0) as v FROM financial_charges fc
        JOIN contracts ct ON fc.contract_id=ct.id
        WHERE fc.status="paid" AND fc.paid_date>=? AND ct.type="molhada"''', [month_start], one=True))['v']

    # Operações por tipo (últimos 30 dias)
    ops_por_tipo = rows_to_list(query('''SELECT operation_type, COUNT(*) as count
        FROM queue_operations WHERE DATE(requested_at) >= ?
        GROUP BY operation_type''', [(today - timedelta(days=30)).strftime('%Y-%m-%d')]))

    return jsonify({
        'ocupacao_total': round(occupied/total_spots*100, 1) if total_spots else 0,
        'ocupacao_seca': round(seca_occ/seca_total*100, 1) if seca_total else 0,
        'ocupacao_molhada': round(molhada_occ/molhada_total*100, 1) if molhada_total else 0,
        'vagas_total': total_spots, 'vagas_ocupadas': occupied,
        'vagas_seca_total': seca_total, 'vagas_seca_ocupadas': seca_occ,
        'vagas_molhada_total': molhada_total, 'vagas_molhada_ocupadas': molhada_occ,
        'receita_mes': receita_mes, 'inadimplencia': inadimplencia,
        'pendente': pendente, 'receita_seca': receita_seca,
        'receita_molhada': receita_molhada, 'receita_loja': loja_mes,
        'taxa_inadimplencia': taxa_inadimplencia,
        'total_clientes': total_clientes, 'vip_count': vip_count,
        'total_vessels': total_vessels, 'contratos_ativos': contratos_ativos,
        'queue_hoje': queue_today, 'queue_aguardando': queue_waiting,
        'sla_avg_min': sla_avg, 'os_abertas': os_abertas, 'os_urgentes': os_urgentes,
        'custo_manutencao_mes': custo_manutencao_mes,
        'alertas_nao_lidos': alertas_nao_lidos,
        'ticket_medio_loja': ticket_medio, 'ltv_medio': ltv_medio,
        'ops_por_tipo': ops_por_tipo,
    })

@app.route('/api/analytics/revenue-chart', methods=['GET'])
@token_required
def revenue_chart():
    rows = rows_to_list(query('''SELECT strftime("%Y-%m", paid_date) as month,
        COALESCE(SUM(amount),0) as total
        FROM financial_charges WHERE status="paid" AND paid_date IS NOT NULL
        GROUP BY month ORDER BY month DESC LIMIT 12'''))
    rows.reverse()
    return jsonify(rows)

@app.route('/api/analytics/occupancy-trend', methods=['GET'])
@token_required
def occupancy_trend():
    rows = rows_to_list(query('''SELECT DATE(start_date) as d, COUNT(*) as new_contracts
        FROM contracts GROUP BY DATE(start_date) ORDER BY d DESC LIMIT 30'''))
    return jsonify(rows)

@app.route('/api/analytics/top-clients', methods=['GET'])
@token_required
def top_clients():
    rows = rows_to_list(query('''SELECT c.name, c.tier, c.ltv,
        COUNT(DISTINCT v.id) as vessels,
        COUNT(DISTINCT ct.id) as contracts
        FROM clients c
        LEFT JOIN vessels v ON v.client_id=c.id AND v.active=1
        LEFT JOIN contracts ct ON ct.client_id=c.id AND ct.status="active"
        WHERE c.active=1
        ORDER BY c.ltv DESC LIMIT 10'''))
    return jsonify(rows)

# ─────────────────────────── DB INIT & SEED ───────────────────────────
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT DEFAULT "admin"
    );
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT, phone TEXT, cpf TEXT,
        tier TEXT DEFAULT "standard", ltv REAL DEFAULT 0,
        address TEXT, notes TEXT, active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS vessels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL, name TEXT NOT NULL,
        type TEXT, length REAL, beam REAL, draft REAL,
        year INTEGER, registration TEXT, model TEXT,
        manufacturer TEXT, engine TEXT, notes TEXT,
        active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (client_id) REFERENCES clients(id)
    );
    CREATE TABLE IF NOT EXISTS spots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        number TEXT NOT NULL, type TEXT NOT NULL,
        status TEXT DEFAULT "available", vessel_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS contracts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL, vessel_id INTEGER NOT NULL,
        spot_id INTEGER, type TEXT NOT NULL,
        start_date TEXT NOT NULL, end_date TEXT,
        monthly_value REAL NOT NULL, status TEXT DEFAULT "active",
        notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (client_id) REFERENCES clients(id),
        FOREIGN KEY (vessel_id) REFERENCES vessels(id)
    );
    CREATE TABLE IF NOT EXISTS queue_operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vessel_id INTEGER NOT NULL, client_id INTEGER NOT NULL,
        operation_type TEXT NOT NULL, status TEXT DEFAULT "waiting",
        priority INTEGER DEFAULT 0, requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
        started_at TEXT, completed_at TEXT, operator TEXT, notes TEXT
    );
    CREATE TABLE IF NOT EXISTS financial_charges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL, contract_id INTEGER,
        description TEXT NOT NULL, amount REAL NOT NULL,
        due_date TEXT NOT NULL, paid_date TEXT,
        payment_method TEXT, status TEXT DEFAULT "pending",
        notes TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS store_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, category TEXT, price REAL NOT NULL,
        cost REAL DEFAULT 0, stock INTEGER DEFAULT 0,
        min_stock INTEGER DEFAULT 5, unit TEXT DEFAULT "un",
        active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS store_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vessel_id INTEGER, client_id INTEGER,
        items TEXT NOT NULL, subtotal REAL NOT NULL,
        discount REAL DEFAULT 0, total REAL NOT NULL,
        status TEXT DEFAULT "open", payment_method TEXT,
        pix_txid TEXT, notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS store_pix_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL, key_type TEXT NOT NULL,
        merchant_name TEXT NOT NULL, city TEXT NOT NULL,
        active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS maintenance_os (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vessel_id INTEGER, os_number TEXT NOT NULL,
        type TEXT NOT NULL, description TEXT NOT NULL,
        status TEXT DEFAULT "open", priority TEXT DEFAULT "normal",
        scheduled_date TEXT, completed_date TEXT,
        estimated_hours REAL, actual_hours REAL,
        cost REAL DEFAULT 0, technician TEXT,
        parts_used TEXT, notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL, message TEXT NOT NULL,
        severity TEXT DEFAULT "info", entity_type TEXT,
        entity_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        read_at TEXT
    );
    ''')
    db.commit()
    db.close()

def seed_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0:
        db.close()
        return

    pw = hashlib.sha256('marina123'.encode()).hexdigest()
    db.execute("INSERT INTO users (email,password_hash,name,role) VALUES (?,?,?,?)",
               ['admin@marina.com', pw, 'Administrador', 'admin'])

    # Vagas: 90 secas + 20 molhadas
    for i in range(1, 91):
        db.execute("INSERT INTO spots (number,type,status) VALUES (?,?,?)",
                   [f'S{i:03d}', 'seca', 'available'])
    for i in range(1, 21):
        db.execute("INSERT INTO spots (number,type,status) VALUES (?,?,?)",
                   [f'M{i:02d}', 'molhada', 'available'])

    # Clientes
    clients_data = [
        ('Carlos Eduardo Souza', 'carlos@email.com', '(11) 99999-0001', '123.456.789-01', 'vip', 'Av. Beira Mar, 100'),
        ('Ana Paula Ferreira', 'ana@email.com', '(11) 99999-0002', '234.567.890-02', 'gold', 'Rua das Flores, 200'),
        ('Roberto Alves Lima', 'roberto@email.com', '(11) 99999-0003', '345.678.901-03', 'gold', 'Alameda Santos, 300'),
        ('Mariana Costa Pinto', 'mariana@email.com', '(11) 99999-0004', '456.789.012-04', 'silver', 'Rua Augusta, 400'),
        ('Fernando Oliveira', 'fernando@email.com', '(11) 99999-0005', '567.890.123-05', 'silver', 'Av. Paulista, 500'),
        ('Juliana Santos Cruz', 'juliana@email.com', '(11) 99999-0006', '678.901.234-06', 'standard', 'Rua 7 de Abril, 600'),
        ('Marcelo Rodrigues', 'marcelo@email.com', '(11) 99999-0007', '789.012.345-07', 'standard', 'Av. Brasil, 700'),
        ('Patrícia Mendes Luz', 'patricia@email.com', '(11) 99999-0008', '890.123.456-08', 'vip', 'Rua Consolação, 800'),
    ]
    client_ids = []
    for c in clients_data:
        cur = db.execute("INSERT INTO clients (name,email,phone,cpf,tier,address) VALUES (?,?,?,?,?,?)", c)
        client_ids.append(cur.lastrowid)

    # Embarcações
    vessels_data = [
        (client_ids[0], 'Rei dos Mares', 'lancha', 12.5, 3.2, 1.0, 2020, 'SP-1001', 'Phantom 45', 'Phantom', 'Diesel 600cv'),
        (client_ids[1], 'Brisa do Mar', 'veleiro', 10.0, 3.0, 1.5, 2018, 'SP-1002', 'Bavaria 33', 'Bavaria', 'Vela'),
        (client_ids[2], 'Pégaso', 'lancha', 9.5, 2.8, 0.9, 2021, 'SP-1003', 'Focker 295', 'Focker', 'Diesel 400cv'),
        (client_ids[3], 'Sereia', 'lancha', 7.5, 2.5, 0.7, 2019, 'SP-1004', 'Coral 28', 'Coral', 'Gasolina 280cv'),
        (client_ids[4], 'Delfim', 'jetski', 3.5, 1.2, 0.4, 2022, 'SP-1005', 'Sea-Doo 300', 'Sea-Doo', 'Gasolina 300cv'),
        (client_ids[5], 'Maré Alta', 'lancha', 8.0, 2.6, 0.8, 2017, 'SP-1006', 'Ventura 28', 'Ventura', 'Gasolina 220cv'),
        (client_ids[6], 'Sol Poente', 'catamarã', 11.0, 5.0, 0.8, 2020, 'SP-1007', 'Leopard 38', 'Leopard', 'Diesel 2x55cv'),
        (client_ids[7], 'Tempestade', 'lancha', 13.0, 3.5, 1.1, 2023, 'SP-1008', 'Azimut 45', 'Azimut', 'Diesel 2x800cv'),
    ]
    vessel_ids = []
    for v in vessels_data:
        cur = db.execute("INSERT INTO vessels (client_id,name,type,length,beam,draft,year,registration,model,manufacturer,engine) VALUES (?,?,?,?,?,?,?,?,?,?,?)", v)
        vessel_ids.append(cur.lastrowid)

    # Contratos (6 secos, 2 molhados)
    today = date.today()
    start = (today - timedelta(days=180)).strftime('%Y-%m-%d')
    end = (today + timedelta(days=180)).strftime('%Y-%m-%d')
    contracts_data = [
        (client_ids[0], vessel_ids[0], 1, 'seca', 3500.00),
        (client_ids[1], vessel_ids[1], 2, 'seca', 3200.00),
        (client_ids[2], vessel_ids[2], 3, 'seca', 2800.00),
        (client_ids[3], vessel_ids[3], 4, 'seca', 2200.00),
        (client_ids[4], vessel_ids[4], 5, 'seca', 1500.00),
        (client_ids[5], vessel_ids[5], 6, 'seca', 1800.00),
        (client_ids[6], vessel_ids[6], 91, 'molhada', 4500.00),
        (client_ids[7], vessel_ids[7], 92, 'molhada', 5500.00),
    ]
    contract_ids = []
    for ct in contracts_data:
        cur = db.execute('''INSERT INTO contracts (client_id,vessel_id,spot_id,type,start_date,end_date,monthly_value,status)
                            VALUES (?,?,?,?,?,?,?,?)''',
                         [ct[0], ct[1], ct[2], ct[3], start, end, ct[4], 'active'])
        contract_ids.append(cur.lastrowid)
        db.execute('UPDATE spots SET status="occupied", vessel_id=? WHERE id=?', [ct[1], ct[2]])

    # Cobranças históricas (30 dias)
    ct_info = list(zip(client_ids[:8], contract_ids, [c[4] for c in contracts_data]))
    for i in range(30, 0, -1):
        d_str = (today - timedelta(days=i)).strftime('%Y-%m-%d')
        for idx, (cid, ctid, val) in enumerate(ct_info):
            if i % 30 == 0 or i == 30:
                status = 'paid' if i > 5 else 'pending'
                paid_date = d_str if status == 'paid' else None
                month_label = (today - timedelta(days=i)).strftime('%m/%Y')
                db.execute('''INSERT INTO financial_charges (client_id,contract_id,description,amount,due_date,paid_date,status,payment_method)
                              VALUES (?,?,?,?,?,?,?,?)''',
                           [cid, ctid, f'Mensalidade {month_label}', val, d_str, paid_date, status,
                            'pix' if status == 'paid' else None])

    # Cobranças adicionais variadas
    extra_charges = [
        (client_ids[0], None, 'Serviço de içamento emergencial', 850.0,
         (today - timedelta(days=15)).strftime('%Y-%m-%d'), (today - timedelta(days=15)).strftime('%Y-%m-%d'), 'paid', 'cartao'),
        (client_ids[1], None, 'Limpeza casco completa', 420.0,
         (today - timedelta(days=10)).strftime('%Y-%m-%d'), (today - timedelta(days=9)).strftime('%Y-%m-%d'), 'paid', 'pix'),
        (client_ids[2], None, 'Pernoite embarcação visitante', 200.0,
         (today - timedelta(days=8)).strftime('%Y-%m-%d'), None, 'overdue', None),
        (client_ids[3], None, 'Energia elétrica extra', 180.0,
         (today - timedelta(days=6)).strftime('%Y-%m-%d'), None, 'overdue', None),
        (client_ids[7], None, 'Reforma box armazenagem', 1200.0,
         (today + timedelta(days=5)).strftime('%Y-%m-%d'), None, 'pending', None),
    ]
    for ec in extra_charges:
        db.execute('''INSERT INTO financial_charges (client_id,contract_id,description,amount,due_date,paid_date,status,payment_method)
                      VALUES (?,?,?,?,?,?,?,?)''', list(ec))

    # Atualizar LTV
    for cid in client_ids:
        r = db.execute('SELECT COALESCE(SUM(amount),0) as t FROM financial_charges WHERE client_id=? AND status="paid"', [cid]).fetchone()
        db.execute('UPDATE clients SET ltv=? WHERE id=?', [r['t'], cid])

    # Loja - itens
    store_items = [
        ('Óleo Motor 4T 1L', 'manutencao', 45.90, 28.0, 30, 10, 'un'),
        ('Óleo Motor 2T 1L', 'manutencao', 38.50, 22.0, 25, 10, 'un'),
        ('Fluido Hidráulico 1L', 'manutencao', 52.00, 30.0, 20, 5, 'un'),
        ('Graxa Marítima 500g', 'manutencao', 28.90, 15.0, 40, 10, 'un'),
        ('Fita Isolante Marítima', 'equipamento', 18.50, 8.0, 50, 15, 'un'),
        ('Colete Salva-vidas Adulto', 'equipamento', 220.00, 140.0, 15, 5, 'un'),
        ('Colete Infantil', 'equipamento', 180.00, 110.0, 8, 3, 'un'),
        ('Corda Náutica 10m', 'equipamento', 65.00, 35.0, 20, 5, 'un'),
        ('Âncora 5kg', 'equipamento', 380.00, 250.0, 6, 2, 'un'),
        ('Extintor CO2 2kg', 'equipamento', 145.00, 90.0, 12, 4, 'un'),
        ('Cerveja Lata 350ml', 'bebida', 8.00, 3.5, 120, 30, 'un'),
        ('Água Mineral 500ml', 'bebida', 4.00, 1.5, 200, 50, 'un'),
        ('Refrigerante Lata', 'bebida', 7.00, 3.0, 80, 20, 'un'),
        ('Energético 250ml', 'bebida', 12.00, 6.0, 60, 15, 'un'),
        ('Salgadinho Pacote', 'alimento', 6.50, 3.0, 100, 20, 'un'),
        ('Barra de Cereal', 'alimento', 4.50, 2.0, 80, 20, 'un'),
        ('Protetor Solar FPS60', 'outros', 35.00, 18.0, 45, 10, 'un'),
        ('Toalha de Praia', 'outros', 55.00, 28.0, 20, 5, 'un'),
        ('Limpador Embarcação 1L', 'limpeza', 42.00, 22.0, 30, 8, 'un'),
        ('Esponja Marítima', 'limpeza', 12.00, 5.0, 60, 15, 'un'),
    ]
    item_ids = []
    for si in store_items:
        cur = db.execute('INSERT INTO store_items (name,category,price,cost,stock,min_stock,unit) VALUES (?,?,?,?,?,?,?)', si)
        item_ids.append(cur.lastrowid)

    # PIX config padrão
    db.execute("INSERT INTO store_pix_config (key,key_type,merchant_name,city,active) VALUES (?,?,?,?,1)",
               ['11999990000', 'telefone', 'Marina One', 'São Paulo'])

    # Pedidos históricos (últimos 30 dias)
    for i in range(25, 0, -1):
        d_str = (today - timedelta(days=i)).strftime('%Y-%m-%d %H:%M:%S')
        cidx = random.randint(0, 7)
        vidx = random.randint(0, 7)
        n_items = random.randint(1, 4)
        order_items = []
        for _ in range(n_items):
            iidx = random.randint(0, len(item_ids)-1)
            qty = random.randint(1, 3)
            price = store_items[iidx][2]
            order_items.append({'item_id': item_ids[iidx], 'name': store_items[iidx][0], 'qty': qty, 'price': price})
        subtotal = sum(x['qty'] * x['price'] for x in order_items)
        db.execute('''INSERT INTO store_orders (vessel_id,client_id,items,subtotal,discount,total,status,payment_method,created_at)
                      VALUES (?,?,?,?,?,?,?,?,?)''',
                   [vessel_ids[vidx], client_ids[cidx], json.dumps(order_items),
                    subtotal, 0, subtotal, 'paid',
                    random.choice(['dinheiro','pix','cartao']), d_str])

    # Fila de operações históricas
    op_types = ['descida', 'subida', 'atracacao']
    operators = ['João Silva', 'Pedro Santos', 'Maria Oliveira']
    for i in range(20, 0, -1):
        d_start = (today - timedelta(days=i)).strftime('%Y-%m-%d %H:00:00')
        d_end = (today - timedelta(days=i)).strftime('%Y-%m-%d %H:30:00')
        vidx = random.randint(0, 7)
        db.execute('''INSERT INTO queue_operations (vessel_id,client_id,operation_type,status,requested_at,started_at,completed_at,operator)
                      VALUES (?,?,?,?,?,?,?,?)''',
                   [vessel_ids[vidx], client_ids[vidx],
                    random.choice(op_types), 'completed',
                    d_start, d_start, d_end, random.choice(operators)])

    # Fila ativa
    active_ops = [
        (vessel_ids[0], client_ids[0], 'descida', 'waiting', 1),
        (vessel_ids[3], client_ids[3], 'subida', 'in_progress', 0),
        (vessel_ids[6], client_ids[6], 'atracacao', 'waiting', 1),
    ]
    for op in active_ops:
        db.execute('''INSERT INTO queue_operations (vessel_id,client_id,operation_type,status,priority)
                      VALUES (?,?,?,?,?)''', list(op))

    # Manutenção
    maintenance_data = [
        (vessel_ids[0], 'OS-20240101-001', 'preventiva', 'Revisão anual motor', 'completed', 'normal',
         (today-timedelta(days=20)).strftime('%Y-%m-%d'), (today-timedelta(days=18)).strftime('%Y-%m-%d'), 4.0, 3.5, 850.0, 'João Mecânico'),
        (vessel_ids[1], 'OS-20240102-002', 'preventiva', 'Troca de óleo e filtros', 'completed', 'normal',
         (today-timedelta(days=15)).strftime('%Y-%m-%d'), (today-timedelta(days=14)).strftime('%Y-%m-%d'), 2.0, 1.5, 320.0, 'Pedro Técnico'),
        (vessel_ids[2], 'OS-20240103-003', 'corretiva', 'Reparo no sistema de direção', 'in_progress', 'high',
         (today-timedelta(days=5)).strftime('%Y-%m-%d'), None, 6.0, None, 1200.0, 'João Mecânico'),
        (vessel_ids[3], 'OS-20240104-004', 'corretiva', 'Substituição bomba d\'água', 'open', 'urgent',
         today.strftime('%Y-%m-%d'), None, 3.0, None, 650.0, None),
        (vessel_ids[4], 'OS-20240105-005', 'preventiva', 'Lubrificação geral e revisão', 'open', 'normal',
         (today+timedelta(days=7)).strftime('%Y-%m-%d'), None, 2.0, None, 280.0, None),
        (vessel_ids[7], 'OS-20240106-006', 'preventiva', 'Revisão elétrica completa', 'open', 'high',
         (today+timedelta(days=3)).strftime('%Y-%m-%d'), None, 8.0, None, 2200.0, 'Maria Elétrica'),
    ]
    for m in maintenance_data:
        db.execute('''INSERT INTO maintenance_os (vessel_id,os_number,type,description,status,priority,
                      scheduled_date,completed_date,estimated_hours,actual_hours,cost,technician)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''', list(m))

    # Alertas iniciais
    alerts_data = [
        ('financeiro', '2 cobranças em atraso - total R$ 380,00', 'warning'),
        ('manutencao', 'OS urgente: Substituição bomba d\'água - Sereia', 'error'),
        ('estoque', 'Estoque baixo: Âncora 5kg (6 un)', 'warning'),
        ('contrato', '3 contratos vencem em 30 dias', 'info'),
        ('sistema', 'Backup automático realizado com sucesso', 'info'),
    ]
    for a in alerts_data:
        db.execute('INSERT INTO alerts (type,message,severity) VALUES (?,?,?)', list(a))

    db.commit()
    db.close()
    print("✅ Banco de dados inicializado com dados de exemplo!")

if __name__ == '__main__':
    init_db()
    seed_db()
    app.run(host='0.0.0.0', port=3001, debug=False)
