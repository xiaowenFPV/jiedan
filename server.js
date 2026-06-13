const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3456;
const DATA_DIR = path.join(__dirname, 'data');
const SAFETY_CODE = '123456';
const ADMIN_KEY = '880123';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ============ 数据文件读写 ============
function readData(name) {
    const file = path.join(DATA_DIR, name + '.json');
    if (!fs.existsSync(file)) return [];
    const raw = fs.readFileSync(file, 'utf-8');
    return JSON.parse(raw);
}

function writeData(name, data) {
    const file = path.join(DATA_DIR, name + '.json');
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
}

// ============ 种子数据 ============
function seedData() {
    if (!fs.existsSync(path.join(DATA_DIR, 'users.json'))) writeData('users', []);
    if (!fs.existsSync(path.join(DATA_DIR, 'services.json'))) writeData('services', []);
    if (!fs.existsSync(path.join(DATA_DIR, 'orders.json'))) writeData('orders', []);
    if (!fs.existsSync(path.join(DATA_DIR, 'tokens.json'))) writeData('tokens', []);
}
seedData();

// ============ Token 管理 ============
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function getTokenRecord(token) {
    const tokens = readData('tokens');
    return tokens.find(t => t.token === token);
}

function setToken(token, userId, role) {
    const tokens = readData('tokens');
    tokens.push({ token, userId, role: role || null, createdAt: Date.now() });
    writeData('tokens', tokens);
}

function removeToken(token) {
    let tokens = readData('tokens');
    tokens = tokens.filter(t => t.token !== token);
    writeData('tokens', tokens);
}

// ============ Auth 中间件 ============
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '未登录，请先登录' });
    }
    const token = authHeader.slice(7);
    const record = getTokenRecord(token);
    if (!record) {
        return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
    if (record.role === 'admin') {
        req.user = { id: 'admin', name: record.userId, role: 'admin' };
        req.token = token;
        return next();
    }
    const users = readData('users');
    const user = users.find(u => u.id === record.userId);
    if (!user) {
        return res.status(401).json({ error: '用户不存在' });
    }
    req.user = user;
    req.token = token;
    next();
}

function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: '仅管理员可操作' });
    next();
}

// ============ API 路由 ============

// 注册
app.post('/api/register', (req, res) => {
    const { name, password, role } = req.body;

    if (!name || !name.trim()) return res.status(400).json({ error: '用户名不能为空' });
    if (!password || password.length < 4) return res.status(400).json({ error: '密码至少4位' });
    if (role !== 'dashi' && role !== 'guke') return res.status(400).json({ error: '角色必须是 dashi 或 guke' });

    if (role === 'dashi') {
        if (req.body.safetyCode !== SAFETY_CODE) {
            return res.status(403).json({ error: '安全码错误，无法注册为打手' });
        }
    }

    const users = readData('users');
    if (users.find(u => u.name === name)) {
        return res.status(409).json({ error: '用户名已存在' });
    }

    const newUser = {
        id: users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1,
        name: name.trim(),
        password: password,
        role: role,
        dashiId: role === 'dashi' ? ('dashi_' + name.trim().toLowerCase().replace(/\s/g, '_')) : null,
        createdAt: Date.now()
    };

    users.push(newUser);
    writeData('users', users);

    const token = generateToken();
    setToken(token, newUser.id, newUser.role);

    const userResp = { id: newUser.id, name: newUser.name, role: newUser.role, dashiId: newUser.dashiId };
    return res.json({ token, user: userResp });
});

// 登录
app.post('/api/login', (req, res) => {
    const { name, password, role } = req.body;

    // 管理员登录
    if (req.body.adminKey === ADMIN_KEY) {
        const token = generateToken();
        setToken(token, name || '管理员', 'admin');
        return res.json({ token, user: { id: 'admin', name: name || '管理员', role: 'admin' } });
    }

    if (!name || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
    if (role !== 'dashi' && role !== 'guke') return res.status(400).json({ error: '角色必须是 dashi 或 guke' });

    if (role === 'dashi') {
        if (req.body.safetyCode !== SAFETY_CODE) {
            return res.status(403).json({ error: '安全码错误' });
        }
    }

    const users = readData('users');
    const user = users.find(u => u.name === name && u.role === role);

    if (!user) return res.status(401).json({ error: '用户不存在，请先注册' });
    if (user.password !== password) return res.status(401).json({ error: '密码错误' });

    const token = generateToken();
    setToken(token, user.id, user.role);

    const userResp = { id: user.id, name: user.name, role: user.role, dashiId: user.dashiId };
    return res.json({ token, user: userResp });
});

// 获取当前用户
app.get('/api/user', authMiddleware, (req, res) => {
    const u = req.user;
    return res.json({ id: u.id, name: u.name, role: u.role, dashiId: u.dashiId });
});

// 退出登录
app.post('/api/logout', authMiddleware, (req, res) => {
    removeToken(req.token);
    return res.json({ ok: true });
});

// ============ 管理员接口 ============
app.get('/api/admin/orders', authMiddleware, adminMiddleware, (req, res) => {
    const orders = readData('orders');
    return res.json(orders);
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
    const users = readData('users');
    const safe = users.map(u => ({ id: u.id, name: u.name, role: u.role, dashiId: u.dashiId, createdAt: u.createdAt }));
    return res.json(safe);
});

app.post('/api/admin/orders/cancel-all', authMiddleware, adminMiddleware, (req, res) => {
    const orders = readData('orders');
    let count = 0;
    for (const o of orders) {
        if (o.status === 'pending' || o.status === 'accepted') {
            o.status = 'cancelled';
            count++;
        }
    }
    writeData('orders', orders);

    const services = readData('services');
    for (const s of services) s.orders = 0;
    writeData('services', services);

    return res.json({ ok: true, msg: '已下架 ' + count + ' 个订单' });
});

app.post('/api/admin/clear', authMiddleware, adminMiddleware, (req, res) => {
    const type = req.body.type;
    if (type === 'orders') {
        writeData('orders', []);
        return res.json({ ok: true, msg: '所有订单已清除' });
    }
    if (type === 'all') {
        writeData('users', []);
        writeData('services', []);
        writeData('orders', []);
        writeData('tokens', []);
        return res.json({ ok: true, msg: '所有数据已清除' });
    }
    res.status(400).json({ error: '请指定 type: orders 或 all' });
});

// ============ 服务接口 ============
app.get('/api/services', (req, res) => {
    const services = readData('services').filter(s => s.status === 'active');
    return res.json(services);
});

app.post('/api/services', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手可发布服务' });

    const { dashiName, rank, type, price, desc } = req.body;
    if (!dashiName || !dashiName.trim()) return res.status(400).json({ error: '打手昵称不能为空' });
    if (!price || price < 10) return res.status(400).json({ error: '价格最低10元' });

    const services = readData('services');
    const newService = {
        id: services.length > 0 ? Math.max(...services.map(s => s.id)) + 1 : 1,
        dashiName: dashiName.trim(),
        dashiId: req.user.dashiId,
        userId: req.user.id,
        rank: rank || '青铜',
        type: type || '代练',
        price: parseInt(price),
        desc: (desc || '').trim(),
        status: 'active',
        tag: 'new',
        orders: 0,
        rating: 5.0
    };

    services.unshift(newService);
    writeData('services', services);
    return res.json(newService);
});

app.delete('/api/services/:id', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi' && req.user.role !== 'admin') return res.status(403).json({ error: '无权限' });

    const services = readData('services');
    const sid = parseInt(req.params.id);
    const s = services.find(s => s.id === sid);
    if (!s) return res.status(404).json({ error: '服务不存在' });
    if (req.user.role !== 'admin' && s.dashiId !== req.user.dashiId) return res.status(403).json({ error: '只能下架自己的服务' });

    s.status = 'removed';
    writeData('services', services);
    return res.json({ ok: true });
});

// ============ 订单接口 ============
app.post('/api/orders', authMiddleware, (req, res) => {
    if (req.user.role !== 'guke') return res.status(403).json({ error: '仅顾客可下单' });

    const { serviceId, gameId, curRank, targetRank, note } = req.body;
    if (!gameId || !gameId.trim()) return res.status(400).json({ error: '游戏ID不能为空' });

    const services = readData('services');
    const s = services.find(s => s.id === serviceId && s.status === 'active');
    if (!s) return res.status(404).json({ error: '服务不存在或已下架' });

    const orders = readData('orders');
    const newOrder = {
        id: orders.length > 0 ? Math.max(...orders.map(o => o.id)) + 1 : 1,
        serviceId: s.id,
        dashiName: s.dashiName,
        dashiId: s.dashiId,
        customerName: req.user.name,
        customerId: req.user.id,
        gameId: gameId.trim(),
        curRank: curRank || '青铜',
        targetRank: targetRank || '白银',
        type: s.type,
        price: s.price,
        note: (note || '').trim(),
        status: 'pending',
        time: new Date().toLocaleString('zh-CN', { hour12: false }).replace(/\//g, '-')
    };

    orders.unshift(newOrder);
    s.orders = (s.orders || 0) + 1;
    writeData('orders', orders);
    writeData('services', services);
    return res.json(newOrder);
});

app.get('/api/orders/my', authMiddleware, (req, res) => {
    const orders = readData('orders');
    let myOrders;
    if (req.user.role === 'dashi') {
        myOrders = orders.filter(o => o.dashiId === req.user.dashiId);
    } else {
        myOrders = orders.filter(o => o.customerId === req.user.id);
    }
    return res.json(myOrders);
});

app.put('/api/orders/:id/accept', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手可操作' });
    const orders = readData('orders');
    const oid = parseInt(req.params.id);
    const o = orders.find(o => o.id === oid);
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.dashiId !== req.user.dashiId) return res.status(403).json({ error: '只能操作自己的订单' });
    if (o.status !== 'pending') return res.status(400).json({ error: '订单状态不是待确认' });
    o.status = 'accepted';
    writeData('orders', orders);
    return res.json(o);
});

app.put('/api/orders/:id/reject', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手可操作' });
    const orders = readData('orders');
    const oid = parseInt(req.params.id);
    const o = orders.find(o => o.id === oid);
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.dashiId !== req.user.dashiId) return res.status(403).json({ error: '只能操作自己的订单' });
    if (o.status !== 'pending') return res.status(400).json({ error: '订单状态不是待确认' });
    o.status = 'rejected';
    const services = readData('services');
    const s = services.find(s => s.id === o.serviceId);
    if (s) s.orders = Math.max(0, (s.orders || 1) - 1);
    writeData('services', services);
    writeData('orders', orders);
    return res.json(o);
});

app.put('/api/orders/:id/complete', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手可操作' });
    const orders = readData('orders');
    const oid = parseInt(req.params.id);
    const o = orders.find(o => o.id === oid);
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.dashiId !== req.user.dashiId) return res.status(403).json({ error: '只能操作自己的订单' });
    if (o.status !== 'accepted') return res.status(400).json({ error: '订单状态不是进行中' });
    o.status = 'completed';
    writeData('orders', orders);
    return res.json(o);
});

app.put('/api/orders/:id/cancel', authMiddleware, (req, res) => {
    if (req.user.role !== 'guke') return res.status(403).json({ error: '仅顾客可操作' });
    const orders = readData('orders');
    const oid = parseInt(req.params.id);
    const o = orders.find(o => o.id === oid);
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.customerId !== req.user.id) return res.status(403).json({ error: '只能操作自己的订单' });
    if (o.status !== 'pending') return res.status(400).json({ error: '订单状态不是待确认' });
    o.status = 'cancelled';
    const services = readData('services');
    const s = services.find(s => s.id === o.serviceId);
    if (s) s.orders = Math.max(0, (s.orders || 1) - 1);
    writeData('services', services);
    writeData('orders', orders);
    return res.json(o);
});

// 排行榜
app.get('/api/rank', (req, res) => {
    const services = readData('services').filter(s => s.status === 'active' && s.orders > 0);
    const sorted = services.sort((a, b) => (b.orders || 0) - (a.orders || 0)).slice(0, 10);
    const rank = sorted.map((s, i) => ({
        rank: i + 1,
        name: s.dashiName,
        score: s.orders || 0
    }));
    return res.json(rank);
});

// SPA 回退
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: '接口不存在' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log('接单平台服务已启动：http://localhost:' + PORT);
});
