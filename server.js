const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');
const qs = require('querystring');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3456;
const DATA_DIR = path.join(__dirname, 'data');
const SAFETY_CODES = { pc: '123456', mobile: '654321' };
const ADMIN_KEY = '880123';

// ============ NestPay 易支付配置 ============
const EPAY_CONFIG = {
    pid: process.env.EPAY_PID || '2088134367467082',
    key: process.env.EPAY_KEY || 'BMPV8VU723MQXY5ULI1PCKCLHYJO13JS',
    apiUrl: process.env.EPAY_API_URL || 'https://nestpay.cn'
};

// 易支付签名：参数名 ASCII 排序 + key → MD5 大写
function epaySign(params) {
    const sorted = Object.keys(params)
        .filter(k => k !== 'sign' && k !== 'sign_type' && params[k] !== '' && params[k] !== undefined && params[k] !== null)
        .sort();
    const str = sorted.map(k => k + '=' + params[k]).join('&') + '&key=' + EPAY_CONFIG.key;
    return crypto.createHash('md5').update(str, 'utf8').digest('hex').toUpperCase();
}

// HTTP POST 助手（用于调用易支付 API）
function httpPost(url, formData) {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const body = new URLSearchParams(formData).toString();
        const options = {
            hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
        };
        const req = https.request(options, (resp) => {
            let data = '';
            resp.on('data', c => data += c);
            resp.on('end', () => {
                try { resolve(JSON.parse(data)); } catch { resolve(data); }
            });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

function httpGet(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (resp) => {
            let data = '';
            resp.on('data', c => data += c);
            resp.on('end', () => {
                try { resolve(JSON.parse(data)); } catch { resolve(data); }
            });
        }).on('error', reject);
    });
}

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

// ============ 服务配置（优先从文件加载） ============
function loadServiceConfig() {
    const file = path.join(DATA_DIR, 'services.json');
    if (fs.existsSync(file)) {
        try {
            const cfg = JSON.parse(fs.readFileSync(file, 'utf-8'));
            if (cfg && Array.isArray(cfg.services) && cfg.services.length > 0 && cfg.fee) return cfg;
        } catch (_) { /* fall through */ }
    }
    const defaults = {
        services: [
            { id: 'paodao', name: '跑刀', unitPrice: 1, unitAmount: '500w游戏币' },
            { id: 'huhang', name: '护航', unitPrice: 50, unitAmount: '1局' }
        ],
        fee: { platform: 0.15, alipay: 0.006, dashi: 0.844 }
    };
    writeData('services', defaults);
    return defaults;
}
const serviceConfig = loadServiceConfig();
const SERVICE_TYPES = serviceConfig.services;
const FEE = serviceConfig.fee;

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
    const { name, password, role, platform, safeCode } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: '用户名不能为空' });
    if (!password || password.length < 4) return res.status(400).json({ error: '密码至少4位' });
    if (role !== 'dashi' && role !== 'guke') return res.status(400).json({ error: '角色无效' });
    if (role === 'dashi') {
        if (!platform || (!SAFETY_CODES[platform])) return res.status(400).json({ error: '请选择平台（手游/端游）' });
        if (!safeCode || safeCode !== SAFETY_CODES[platform]) return res.status(403).json({ error: '安全码错误' });
    }
    const users = readData('users');
    if (users.find(u => u.name === name)) return res.status(409).json({ error: '用户名已存在' });
    const newUser = {
        id: users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1,
        name: name.trim(), password, role,
        dashiId: role === 'dashi' ? ('dashi_' + name.trim().toLowerCase().replace(/\s/g, '_')) : null,
        platform: role === 'dashi' ? platform : null,
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
    if (role === 'dashi') {
        const platform = req.body.platform;
        if (!platform || !SAFETY_CODES[platform] || req.body.safetyCode !== SAFETY_CODES[platform]) return res.status(403).json({ error: '安全码错误' });
    }
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
    const { typeId, quantity, gameId, note, platform } = req.body;
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
        paidAt: null, platform: platform || null
    };
    orders.unshift(newOrder);
    writeData('orders', orders);
    return res.json(newOrder);
});

// ============ 支付 ============
app.post('/api/pay/create', authMiddleware, async (req, res) => {
    try {
        const { orderId, payType } = req.body;
        const orders = readData('orders');
        const o = orders.find(o => o.id === orderId);
        if (!o) return res.status(404).json({ error: '订单不存在' });
        if (o.customerId !== req.user.id) return res.status(403).json({ error: '权限不足' });
        if (o.status !== 'unpaid') return res.status(400).json({ error: '状态不允许支付' });
        const outTradeNo = 'ORDER_' + orderId + '_' + Date.now();
        const notifyUrl = process.env.PAY_NOTIFY_URL
            || process.env.RENDER_EXTERNAL_URL
            || ('https://' + (req.get('host') || 'hjm-8nbq.onrender.com') + '/api/pay/notify');
        console.log('[pay-create] notify_url =', notifyUrl);
        const productName = '三角洲-' + o.typeName + ' x' + o.quantity;
        const clientIp = req.headers['x-forwarded-for'] || req.ip || '127.0.0.1';
        const params = {
            pid: EPAY_CONFIG.pid,
            type: payType || 'alipay',
            paytype_code: payType || 'alipay',
            out_trade_no: outTradeNo,
            notify_url: notifyUrl,
            name: productName,
            subject: productName,
            total_amount: o.totalPrice.toFixed(2),
            client_ip: clientIp,
            timestamp: Math.floor(Date.now() / 1000),
            sign_type: 'MD5'
        };
        params.sign = epaySign(params);
        const result = await httpPost(EPAY_CONFIG.apiUrl + '/openapi/pay/create', params);
        if (result.code !== 1) {
            return res.status(400).json({ error: '支付网关: ' + (result.msg || '未知错误') });
        }
        o.epayOutTradeNo = outTradeNo;
        o.payType = params.type;
        writeData('orders', orders);
        return res.json({ payUrl: result.data && result.data.pay_url, orderId, outTradeNo, payType: params.type });
    } catch (err) { console.error(err); res.status(500).json({ error: '支付初始化失败: ' + err.message }); }
});

app.post('/api/pay/status/:id', authMiddleware, async (req, res) => {
    try {
        const orders = readData('orders');
        const o = orders.find(o => o.id === parseInt(req.params.id));
        if (!o) return res.status(404).json({ error: '订单不存在' });
        if (o.status !== 'unpaid') return res.json({ paid: true, order: o });
        if (!o.epayOutTradeNo) return res.json({ paid: false });
        const params = {
            pid: EPAY_CONFIG.pid,
            out_trade_no: o.epayOutTradeNo,
            timestamp: Math.floor(Date.now() / 1000),
            sign_type: 'MD5'
        };
        params.sign = epaySign(params);
        const result = await httpPost(EPAY_CONFIG.apiUrl + '/openapi/pay/query', params);
        if (result.code === 1 && result.data && result.data.trade_status === 'TRADE_SUCCESS') {
            o.status = 'pending';
            o.paidAt = new Date().toLocaleString('zh-CN', { hour12: false }).replace(/\//g, '-');
            writeData('orders', orders);
            return res.json({ paid: true, order: o });
        }
        return res.json({ paid: false });
    } catch { return res.json({ paid: false }); }
});

app.post('/api/pay/notify', express.text({ type: '*/*' }), (req, res) => {
    console.log('[pay-notify] ========== 收到回调 ==========');
    // 兜底：如果全局 body parser 未解析（Content-Type 不匹配），手动从 text body 解析
    if (!req.body || Object.keys(req.body).length === 0 || typeof req.body === 'string') {
        const rawBody = typeof req.body === 'string' ? req.body : '';
        console.log('[pay-notify] body parser 未生效，手动解析，Content-Type:', req.get('Content-Type'));
        console.log('[pay-notify] raw body (前300字):', rawBody.substring(0, 300));
        req.body = qs.parse(rawBody);
    }
    const body = req.body;
    console.log('[pay-notify] raw body:', JSON.stringify(body));
    console.log('[pay-notify] all keys:', Object.keys(body).sort());
    const receivedSign = body.sign;
    if (!receivedSign) {
        console.log('[pay-notify] 缺少 sign 字段');
        return res.send('fail');
    }
    // 验签：剥离 sign / sign_type 后计算签名（确保值统一为字符串）
    const signParams = {};
    for (const [k, v] of Object.entries(body)) {
        if (k === 'sign' || k === 'sign_type') continue;
        signParams[k] = String(v ?? '');
    }
    const sorted = Object.keys(signParams).filter(k => signParams[k] !== '').sort();
    console.log('[pay-notify] sign string (w/o key):', sorted.map(k => k + '=' + signParams[k]).join('&') + '&key=***');
    const computedSign = epaySign(signParams);
    console.log('[pay-notify] computedSign:', computedSign);
    console.log('[pay-notify] receivedSign:', receivedSign);
    if (receivedSign !== computedSign) {
        console.log('[pay-notify] 签名不匹配！');
        return res.send('fail');
    }
    console.log('[pay-notify] 签名验证通过！');
    if (body.trade_status === 'TRADE_SUCCESS') {
        const orders = readData('orders');
        const o = orders.find(o => o.epayOutTradeNo === body.out_trade_no);
        if (o && o.status === 'unpaid') {
            o.status = 'pending';
            o.paidAt = new Date().toLocaleString('zh-CN', { hour12: false }).replace(/\//g, '-');
            o.buyerAccount = body.buyer_email || '';
            writeData('orders', orders);
            console.log('[pay-notify] 订单 ' + o.id + ' 已标记为待接单');
        } else if (!o) {
            console.log('[pay-notify] 未找到订单 out_trade_no=' + body.out_trade_no);
        } else {
            console.log('[pay-notify] 订单 ' + o.id + ' 状态为 ' + o.status + '，跳过');
        }
    } else {
        console.log('[pay-notify] trade_status=' + body.trade_status + '，无需处理');
    }
    res.type('text/plain').send('success');
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

// 管理员新增服务类型
app.post('/api/admin/services/add', authMiddleware, adminMiddleware, (req, res) => {
    const { name, unitPrice, unitAmount, desc } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: '服务名称不能为空' });
    const price = parseFloat(unitPrice);
    if (isNaN(price) || price <= 0) return res.status(400).json({ error: '单价必须为正数' });
    if (!unitAmount || !unitAmount.trim()) return res.status(400).json({ error: '单位描述不能为空' });
    // 自动生成 ID
    const maxNum = SERVICE_TYPES.reduce((max, s) => {
        const m = s.id.match(/^svc_(\d+)$/);
        return m ? Math.max(max, parseInt(m[1])) : max;
    }, 0);
    const newId = 'svc_' + (maxNum + 1);
    const newService = {
        id: newId, name: name.trim(), unitPrice: price,
        unitAmount: unitAmount.trim(), desc: (desc || '').trim(),
        adminCreated: true
    };
    SERVICE_TYPES.push(newService);
    writeData('services', { services: SERVICE_TYPES, fee: FEE });
    return res.json(newService);
});

app.get('/api/admin/services', authMiddleware, adminMiddleware, (req, res) => {
    return res.json({ services: SERVICE_TYPES, fee: FEE });
});

app.put('/api/admin/services', authMiddleware, adminMiddleware, (req, res) => {
    const { services, fee } = req.body;
    if (!Array.isArray(services) || services.length === 0) {
        return res.status(400).json({ error: 'services 必须为非空数组' });
    }
    const validIds = new Set(SERVICE_TYPES.map(s => s.id));
    for (const svc of services) {
        if (!validIds.has(svc.id)) return res.status(400).json({ error: '无效服务ID: ' + svc.id });
        if (!svc.unitPrice || svc.unitPrice <= 0) return res.status(400).json({ error: svc.name + ' 单价必须为正数' });
        if (!svc.name || !svc.name.trim()) return res.status(400).json({ error: '服务名称不能为空' });
    }
    // fee 可选：仅当显式传入且非空对象时才校验和更新费率
    if (fee && typeof fee === 'object' && Object.keys(fee).length > 0) {
        const sum = (fee.platform || 0) + (fee.alipay || 0) + (fee.dashi || 0);
        if (sum < 0.999 || sum > 1.001) return res.status(400).json({ error: '费率合计必须接近1（当前' + sum.toFixed(4) + '）' });
    }
    // 更新内存中的配置
    services.forEach(s => {
        const idx = SERVICE_TYPES.findIndex(x => x.id === s.id);
        if (idx >= 0) {
            SERVICE_TYPES[idx].unitPrice = s.unitPrice;
            SERVICE_TYPES[idx].unitAmount = s.unitAmount || SERVICE_TYPES[idx].unitAmount;
            SERVICE_TYPES[idx].name = s.name.trim();
        }
    });
    if (fee && typeof fee === 'object' && Object.keys(fee).length > 0) { FEE.platform = fee.platform; FEE.alipay = fee.alipay; FEE.dashi = fee.dashi; }
    // 持久化
    writeData('services', { services: SERVICE_TYPES, fee: FEE });
    return res.json({ services: SERVICE_TYPES, fee: FEE });
});

app.get('*', (req, res) => { if (req.path.startsWith('/api/')) return res.status(404).json({ error: '接口不存在' }); res.sendFile(path.join(__dirname, 'public', 'index.html')); });

app.listen(PORT, () => console.log('服务已启动：http://localhost:' + PORT));
