const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { AlipaySdk } = require('alipay-sdk');
// AlipayFormData no longer needed in v4 - params.bizContent used directly

const app = express();
const PORT = process.env.PORT || 3456;
const DATA_DIR = path.join(__dirname, 'data');
const SAFETY_CODE = '123456';
const ADMIN_KEY = '880123';

// ============ 支付宝当面付配置 ============
const ALIPAY_CONFIG = {
    appId: '你的APPID',
    privateKey: `-----BEGIN RSA PRIVATE KEY-----
你的应用私钥
-----END RSA PRIVATE KEY-----`,
    alipayPublicKey: `-----BEGIN PUBLIC KEY-----
你的支付宝公钥
-----END PUBLIC KEY-----`,
    gateway: 'https://openapi.alipay.com/gateway.do',
    charset: 'utf-8',
    version: '1.0',
    signType: 'RSA2'
};

const alipaySdk = new AlipaySdk({
    appId: ALIPAY_CONFIG.appId,
    privateKey: ALIPAY_CONFIG.privateKey,
    alipayPublicKey: ALIPAY_CONFIG.alipayPublicKey,
    gateway: ALIPAY_CONFIG.gateway,
    charset: ALIPAY_CONFIG.charset,
    version: ALIPAY_CONFIG.version,
    signType: ALIPAY_CONFIG.signType
});

// ============ 费率配置 ============
const FEE = {
    platform: 0.15,
    alipay: 0.006,
    dashi: 0.844
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readData(name) {
    const file = path.join(DATA_DIR, name + '.json');
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

function writeData(name, data) {
    fs.writeFileSync(path.join(DATA_DIR, name + '.json'), JSON.stringify(data, null, 2), 'utf-8');
}

function seedData() {
    if (!fs.existsSync(path.join(DATA_DIR, 'users.json'))) writeData('users', []);
    if (!fs.existsSync(path.join(DATA_DIR, 'orders.json'))) writeData('orders', []);
    if (!fs.existsSync(path.join(DATA_DIR, 'tokens.json'))) writeData('tokens', []);
}
seedData();

const SERVICE_TYPES = [
    { id: 'paodao', name: '跑刀', unitPrice: 35, unitAmount: '500w游戏币' },
    { id: 'huhang', name: '护航', unitPrice: 50, unitAmount: '1局' }
];

// Token
function generateToken() { return crypto.randomBytes(32).toString('hex'); }
function getTokenRecord(token) {
    const tokens = readData('tokens');
    return tokens.find(t => t.token === token);
}
function setToken(token, userId, role) {
    const tokens = readData('tokens');
    tokens.push({ token, userId, role, createdAt: Date.now() });
    writeData('tokens', tokens);
}
function removeToken(token) {
    let tokens = readData('tokens');
    tokens = tokens.filter(t => t.token !== token);
    writeData('tokens', tokens);
}

function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: '未登录' });
    const token = authHeader.slice(7);
    const record = getTokenRecord(token);
    if (!record) return res.status(401).json({ error: '登录过期' });
    if (record.role === 'admin') { req.user = { id: 'admin', name: record.userId, role: 'admin' }; req.token = token; return next(); }
    const users = readData('users');
    const user = users.find(u => u.id === record.userId);
    if (!user) return res.status(401).json({ error: '用户不存在' });
    req.user = user;
    req.token = token;
    next();
}

function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: '仅管理员' });
    next();
}

// ============ 基础接口 ============
app.get('/api/types', (req, res) => res.json(SERVICE_TYPES));

app.post('/api/register', (req, res) => {
    const { name, password, role } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: '用户名不能为空' });
    if (!password || password.length < 4) return res.status(400).json({ error: '密码至少4位' });
    if (role !== 'dashi' && role !== 'guke') return res.status(400).json({ error: '角色无效' });
    if (role === 'dashi' && req.body.safetyCode !== SAFETY_CODE) return res.status(403).json({ error: '安全码错误' });
    const users = readData('users');
    if (users.find(u => u.name === name)) return res.status(409).json({ error: '用户名已存在' });
    const newUser = {
        id: users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1,
        name: name.trim(), password, role,
        dashiId: role === 'dashi' ? ('dashi_' + name.trim().toLowerCase().replace(/\s/g, '_')) : null,
        completedOrders: 0, totalEarned: 0, createdAt: Date.now()
    };
    users.push(newUser);
    writeData('users', users);
    const token = generateToken();
    setToken(token, newUser.id, newUser.role);
    return res.json({ token, user: { id: newUser.id, name: newUser.name, role: newUser.role, dashiId: newUser.dashiId } });
});

app.post('/api/login', (req, res) => {
    const { name, password, role } = req.body;
    if (req.body.adminKey === ADMIN_KEY) {
        const token = generateToken();
        setToken(token, name || '管理员', 'admin');
        return res.json({ token, user: { id: 'admin', name: name || '管理员', role: 'admin' } });
    }
    if (!name || !password) return res.status(400).json({ error: '用户名密码不能为空' });
    if (role !== 'dashi' && role !== 'guke') return res.status(400).json({ error: '角色无效' });
    if (role === 'dashi' && req.body.safetyCode !== SAFETY_CODE) return res.status(403).json({ error: '安全码错误' });
    const users = readData('users');
    const user = users.find(u => u.name === name && u.role === role);
    if (!user) return res.status(401).json({ error: '用户不存在' });
    if (user.password !== password) return res.status(401).json({ error: '密码错误' });
    const token = generateToken();
    setToken(token, user.id, user.role);
    return res.json({ token, user: { id: user.id, name: user.name, role: user.role, dashiId: user.dashiId } });
});

app.get('/api/user', authMiddleware, (req, res) => res.json({ id: req.user.id, name: req.user.name, role: req.user.role, dashiId: req.user.dashiId }));

app.post('/api/logout', authMiddleware, (req, res) => { removeToken(req.token); res.json({ ok: true }); });

// ============ 下单 ============
app.post('/api/orders', authMiddleware, (req, res) => {
    if (req.user.role !== 'guke') return res.status(403).json({ error: '仅顾客可下单' });
    const { typeId, quantity, gameId, note } = req.body;
    const st = SERVICE_TYPES.find(s => s.id === typeId);
    if (!st) return res.status(400).json({ error: '无效服务类型' });
    const qty = parseInt(quantity) || 1;
    if (qty < 1 || qty > 100) return res.status(400).json({ error: '数量1-100' });
    if (!gameId || !gameId.trim()) return res.status(400).json({ error: '游戏ID不能为空' });
    const totalPrice = st.unitPrice * qty;
    const platformFee = +(totalPrice * FEE.platform).toFixed(2);
    const alipayFee = +(totalPrice * FEE.alipay).toFixed(2);
    const dashiIncome = +(totalPrice * FEE.dashi).toFixed(2);
    const orders = readData('orders');
    const newOrder = {
        id: orders.length > 0 ? Math.max(...orders.map(o => o.id)) + 1 : 1,
        typeId, typeName: st.name, unitPrice: st.unitPrice, unitAmount: st.unitAmount,
        quantity: qty, totalPrice, platformFee, alipayFee, dashiIncome,
        customerName: req.user.name, customerId: req.user.id, gameId: gameId.trim(),
        note: (note || '').trim(), status: 'unpaid', dashiId: null, dashiName: null,
        time: new Date().toLocaleString('zh-CN', { hour12: false }).replace(/\//g, '-'),
        paidAt: null
    };
    orders.unshift(newOrder);
    writeData('orders', orders);
    return res.json(newOrder);
});

// ============ 支付 ============
app.post('/api/pay/create', authMiddleware, (req, res) => {
    const { orderId } = req.body;
    const orders = readData('orders');
    const o = orders.find(o => o.id === orderId);
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.customerId !== req.user.id) return res.status(403).json({ error: '权限不足' });
    if (o.status !== 'unpaid') return res.status(400).json({ error: '状态不允许支付' });
    const outTradeNo = 'ORDER_' + orderId + '_' + Date.now();
    alipaySdk.exec('alipay.trade.precreate', {
        notifyUrl: process.env.PAY_NOTIFY_URL || (req.protocol + '://' + req.get('host') + '/api/pay/notify'),
        bizContent: {
            outTradeNo, totalAmount: o.totalPrice.toFixed(2),
            subject: '三角洲-' + o.typeName + ' x' + o.quantity,
            body: '游戏ID:' + o.gameId, timeoutExpress: '15m'
        }
    }).then(result => {
        o.alipayOutTradeNo = outTradeNo;
        writeData('orders', orders);
        return res.json({ qrCode: result.qrCode, orderId, outTradeNo });
    }).catch(err => { console.error(err); res.status(500).json({ error: '支付初始化失败' }); });
});

app.get('/api/pay/status/:id', authMiddleware, (req, res) => {
    const orders = readData('orders');
    const o = orders.find(o => o.id === parseInt(req.params.id));
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.status !== 'unpaid') return res.json({ paid: true, order: o });
    if (!o.alipayOutTradeNo) return res.json({ paid: false });
    alipaySdk.exec('alipay.trade.query', {
        bizContent: { outTradeNo: o.alipayOutTradeNo }
    }).then(result => {
        if (result.code === '10000' && result.tradeStatus === 'TRADE_SUCCESS') {
            o.status = 'pending';
            o.paidAt = new Date().toLocaleString('zh-CN', { hour12: false }).replace(/\//g, '-');
            writeData('orders', orders);
            return res.json({ paid: true, order: o });
        }
        return res.json({ paid: false });
    }).catch(() => res.json({ paid: false }));
});

app.post('/api/pay/notify', (req, res) => {
    const body = req.body;
    if (!alipaySdk.checkNotifySign(body)) return res.send('fail');
    if (body.trade_status === 'TRADE_SUCCESS') {
        const orders = readData('orders');
        const o = orders.find(o => o.alipayOutTradeNo === body.out_trade_no);
        if (o && o.status === 'unpaid') {
            o.status = 'pending';
            o.paidAt = new Date().toLocaleString('zh-CN', { hour12: false }).replace(/\//g, '-');
            o.buyerAccount = body.buyer_logon_id || '';
            writeData('orders', orders);
        }
    }
    res.send('success');
});

// ============ 订单操作 ============
app.get('/api/orders/my', authMiddleware, (req, res) => {
    const orders = readData('orders');
    return res.json(req.user.role === 'guke' ? orders.filter(o => o.customerId === req.user.id) : req.user.role === 'dashi' ? orders.filter(o => o.dashiId === req.user.dashiId) : []);
});

app.get('/api/orders/pending', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手' });
    return res.json(readData('orders').filter(o => o.status === 'pending'));
});

app.put('/api/orders/:id/accept', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手' });
    const orders = readData('orders');
    const o = orders.find(o => o.id === parseInt(req.params.id));
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.status !== 'pending') return res.status(400).json({ error: '已被抢走' });
    o.status = 'accepted'; o.dashiId = req.user.dashiId; o.dashiName = req.user.name;
    writeData('orders', orders);
    return res.json(o);
});

app.put('/api/orders/:id/complete', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手' });
    const orders = readData('orders');
    const o = orders.find(o => o.id === parseInt(req.params.id));
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.dashiId !== req.user.dashiId) return res.status(403).json({ error: '非本人订单' });
    if (o.status !== 'accepted') return res.status(400).json({ error: '状态错误' });
    o.status = 'completed';
    const users = readData('users');
    const dashi = users.find(u => u.dashiId === req.user.dashiId);
    if (dashi) { dashi.completedOrders = (dashi.completedOrders || 0) + 1; dashi.totalEarned = +((dashi.totalEarned || 0) + o.dashiIncome).toFixed(2); writeData('users', users); }
    writeData('orders', orders);
    return res.json(o);
});

app.put('/api/orders/:id/settle', authMiddleware, adminMiddleware, (req, res) => {
    const orders = readData('orders');
    const o = orders.find(o => o.id === parseInt(req.params.id));
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.status !== 'completed') return res.status(400).json({ error: '只能结算已完成订单' });
    o.status = 'settled';
    writeData('orders', orders);
    return res.json(o);
});

app.put('/api/orders/:id/cancel', authMiddleware, (req, res) => {
    if (req.user.role !== 'guke') return res.status(403).json({ error: '仅顾客' });
    const orders = readData('orders');
    const o = orders.find(o => o.id === parseInt(req.params.id));
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.customerId !== req.user.id) return res.status(403).json({ error: '非本人订单' });
    if (o.status !== 'unpaid') return res.status(400).json({ error: '只能取消未支付订单' });
    o.status = 'cancelled';
    writeData('orders', orders);
    return res.json(o);
});

// ============ 管理员 ============
app.get('/api/admin/orders', authMiddleware, adminMiddleware, (req, res) => res.json(readData('orders')));

app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
    const users = readData('users');
    return res.json(users.map(u => ({ id: u.id, name: u.name, role: u.role, dashiId: u.dashiId, completedOrders: u.completedOrders || 0, totalEarned: u.totalEarned || 0, createdAt: u.createdAt })));
});

app.post('/api/admin/orders/cancel-all', authMiddleware, adminMiddleware, (req, res) => {
    const orders = readData('orders');
    let c = 0;
    orders.forEach(o => { if (o.status === 'pending' || o.status === 'accepted') { o.status = 'cancelled'; c++; } });
    writeData('orders', orders);
    return res.json({ ok: true, msg: '已下架 ' + c + ' 个订单' });
});

app.post('/api/admin/clear', authMiddleware, adminMiddleware, (req, res) => {
    if (req.body.type === 'orders') { writeData('orders', []); return res.json({ ok: true, msg: '订单已清空' }); }
    if (req.body.type === 'all') { writeData('users', []); writeData('orders', []); writeData('tokens', []); return res.json({ ok: true, msg: '全部清空' }); }
    res.status(400).json({ error: 'type: orders 或 all' });
});

app.get('*', (req, res) => { if (req.path.startsWith('/api/')) return res.status(404).json({ error: '接口不存在' }); res.sendFile(path.join(__dirname, 'public', 'index.html')); });

app.listen(PORT, () => console.log('服务已启动：http://localhost:' + PORT));
