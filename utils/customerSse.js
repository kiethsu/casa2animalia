// utils/customerSse.js
const clients = new Map(); // userId -> Set(res)

function register(userId, res) {
  const uid = String(userId);
  if (!clients.has(uid)) clients.set(uid, new Set());
  clients.get(uid).add(res);
}

function remove(userId, res) {
  const uid = String(userId);
  const set = clients.get(uid);
  if (!set) return;
  if (res) set.delete(res);
  if (!res || set.size === 0) clients.delete(uid);
}

function pushTo(userId, payload) {
  const set = clients.get(String(userId));
  if (!set || set.size === 0) return false;
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const r of set) {
    try { r.write(data); } catch (_) {}
  }
  return true;
}

module.exports = { register, remove, pushTo };
