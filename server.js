const express = require('express');
const path = require('path');
const { Keychain } = require('./password-manager');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let keychain;

(async () => {
    keychain = await Keychain.init('password123!');
})();

// API endpoints
app.post('/set', async (req, res) => {
    const { domain, password } = req.body;
    await keychain.set(domain, password);
    res.json({ success: true });
});

app.post('/get', async (req, res) => {
    const { domain } = req.body;
    const value = await keychain.get(domain);
    res.json({ password: value });
});

app.post('/remove', async (req, res) => {
    const { domain } = req.body;
    const success = await keychain.remove(domain);
    res.json({ success });
});

app.listen(3000, () => console.log('Server running at http://localhost:3000'));
