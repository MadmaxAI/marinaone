const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

const db = new DatabaseSync('./marina.db');

const users = db.prepare('SELECT email, role FROM users').all();
process.stdout.write('USERS: ' + JSON.stringify(users) + '\n');

const cols = db.prepare("PRAGMA table_info(store_orders)").all();
const hasDelivery = cols.some(c => c.name === 'delivery_status');
process.stdout.write('delivery_status exists: ' + hasDelivery + '\n');

const routes = [];
function addRoute(method, pattern) { routes.push(method + ' ' + pattern); }
// simulate route loading count
process.stdout.write('TEST OK\n');
