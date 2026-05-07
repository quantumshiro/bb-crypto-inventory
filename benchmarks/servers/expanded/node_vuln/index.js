
const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/auth', (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).send('Missing token');
    
    const token = auth.split(' ')[1];
    const [headerB64, payloadB64] = token.split('.');
    
    const header = JSON.parse(Buffer.from(headerB64, 'base64').toString());
    
    if (header.alg === 'none') {
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
        return res.json({ authenticated: true, user: payload });
    }
    
    res.status(401).send('Invalid algorithm');
});

app.listen(8083, () => console.log('Node vuln app listening on 8083'));
