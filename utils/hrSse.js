// utils/hrSse.js
const clients = new Set();

function addClient(res) { clients.add(res); }
function removeClient(res) { clients.delete(res); }
function broadcast(payload) {
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of clients) { try { res.write(data); } catch (_) {} }
}

module.exports = { addClient, removeClient, broadcast };

