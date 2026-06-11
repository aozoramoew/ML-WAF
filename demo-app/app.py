"""
Tiny "vulnerable shop" demo app — used to demonstrate ML-WAF protecting a
real backend via the nginx reverse-proxy / auth_request pattern.

Deliberately NOT hardened: SQL queries are built with string concatenation,
search results echo input back unescaped, etc. Do not deploy this anywhere
except behind ML-WAF for demo purposes.
"""

import sqlite3
from pathlib import Path
from flask import Flask, request, g

app = Flask(__name__)
DB_PATH = Path(__file__).parent / 'shop.db'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        DROP TABLE IF EXISTS products;
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        INSERT INTO products (id, name, price) VALUES
            (1, 'Jamon Iberico', 85.0),
            (2, 'Queso Manchego', 18.5),
            (3, 'Aceite de Oliva', 12.0);
    """)
    db.commit()
    db.close()


@app.route('/')
def index():
    return '''
    <h1>Demo Shop (behind ML-WAF)</h1>
    <p><a href="/products?id=1">View product 1</a></p>
    <form action="/search">
      <input name="q" placeholder="search products">
      <button type="submit">Search</button>
    </form>
    '''


@app.route('/products')
def products():
    product_id = request.args.get('id', '1')
    db = get_db()
    # Intentionally vulnerable to SQLi — protected by ML-WAF in front.
    cur = db.execute(f"SELECT id, name, price FROM products WHERE id = {product_id}")
    rows = cur.fetchall()
    return {'products': rows}


@app.route('/search')
def search():
    q = request.args.get('q', '')
    # Intentionally reflects input unescaped — XSS sink, protected by ML-WAF.
    return f'<h2>Results for: {q}</h2><p>No products found.</p>'


@app.route('/health')
def health():
    return {'status': 'ok'}


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
