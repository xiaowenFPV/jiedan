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
    if (!fs.existsSync(path.join(DATA_DIR, 'orders.json'))) writeData('orders', []);
    if (!fs.existsSync(path.join(DATA_DIR, 'tokens.json'))) writeData('tokens', []);
}
seedData();

// ============ 固定服务类型 ============
const SERVICE_TYPES = [
    { id: 'paodao', name: '跑刀', unitPrice: 35, unitAmount: '500w游戏币' },
    { id: 'huhang', name: '护航', unitPrice: 50, unitAmount: '1局' }
];

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
    if (!record) return res.status(401).json({ error: '登录已过期，请重新登录' });
    if (record.role === 'admin') {
        req.user = { id: 'admin', name: record.userId, role: 'admin' };
        req.token = token;
        return next();
    }
    const users = readData('users');
    const user = users.find(u => u.id === record.userId);
    if (!user) return res.status(401).json({ error: '用户不存在' });
    req.user = user;
    req.token = token;
    next();
}

function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: '仅管理员可操作' });
    next();
}

// ============ API 路由 ============

// 获取服务类型
app.get('/api/types', (req, res) => {
    return res.json(SERVICE_TYPES);
});

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
    if (users.find(u => u.name === name)) return res.status(409).json({ error: '用户名已存在' });

    const newUser = {
        id: users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1,
        name: name.trim(),
        password: password,
        role: role,
        dashiId: role === 'dashi' ? ('dashi_' + name.trim().toLowerCase().replace(/\s/g, '_')) : null,
        completedOrders: 0,
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

    if (req.body.adminKey === ADMIN_KEY) {
        const token = generateToken();
        setToken(token, name || '管理员', 'admin');
        return res.json({ token, user: { id: 'admin', name: name || '管理员', role: 'admin' } });
    }

    if (!name || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
    if (role !== 'dashi' && role !== 'guke') return res.status(400).json({ error: '角色必须是 dashi 或 guke' });

    if (role === 'dashi') {
        if (req.body.safetyCode !== SAFETY_CODE) return res.status(403).json({ error: '安全码错误' });
    }

    const users = readData('users');
    const user = users.find(u => u.name === name && u.role === role);
    if (!user) return res.status(401).json({ error: '用户不存在，请先注册' });
    if (user.password !== password) return res.status(401).json({ error: '密码错误' });

    const token = generateToken();
    setToken(token, user.id, user.role);
    return res.json({ token, user: { id: user.id, name: user.name, role: user.role, dashiId: user.dashiId } });
});

app.get('/api/user', authMiddleware, (req, res) => {
    const u = req.user;
    return res.json({ id: u.id, name: u.name, role: u.role, dashiId: u.dashiId });
});

app.post('/api/logout', authMiddleware, (req, res) => {
    removeToken(req.token);
    return res.json({ ok: true });
});

// ============ 下单（顾客） ============
app.post('/api/orders', authMiddleware, (req, res) => {
    if (req.user.role !== 'guke') return res.status(403).json({ error: '仅顾客可下单' });

    const { typeId, quantity, gameId, note } = req.body;
    const st = SERVICE_TYPES.find(s => s.id === typeId);
    if (!st) return res.status(400).json({ error: '无效的服务类型' });

    const qty = parseInt(quantity) || 1;
    if (qty < 1 || qty > 100) return res.status(400).json({ error: '数量必须在1-100之间' });

    if (!gameId || !gameId.trim()) return res.status(400).json({ error: '游戏ID不能为空' });

    const orders = readData('orders');
    const newOrder = {
        id: orders.length > 0 ? Math.max(...orders.map(o => o.id)) + 1 : 1,
        typeId: typeId,
        typeName: st.name,
        unitPrice: st.unitPrice,
        unitAmount: st.unitAmount,
        quantity: qty,
        totalPrice: st.unitPrice * qty,
        customerName: req.user.name,
        customerId: req.user.id,
        gameId: gameId.trim(),
        note: (note || '').trim(),
        status: 'pending',
        dashiId: null,
        dashiName: null,
        time: new Date().toLocaleString('zh-CN', { hour12: false }).replace(/\//g, '-')
    };

    orders.unshift(newOrder);
    writeData('orders', orders);
    return res.json(newOrder);
});

// 获取我的订单
app.get('/api/orders/my', authMiddleware, (req, res) => {
    const orders = readData('orders');
    let myOrders;
    if (req.user.role === 'guke') {
        myOrders = orders.filter(o => o.customerId === req.user.id);
    } else if (req.user.role === 'dashi') {
        myOrders = orders.filter(o => o.dashiId === req.user.dashiId);
    } else {
        myOrders = [];
    }
    return res.json(myOrders);
});

// 打手查看所有待接订单
app.get('/api/orders/pending', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手可查看' });
    const orders = readData('orders').filter(o => o.status === 'pending');
    return res.json(orders);
});

// 打手接单
app.put('/api/orders/:id/accept', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手可操作' });

    const orders = readData('orders');
    const oid = parseInt(req.params.id);
    const o = orders.find(o => o.id === oid);
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.status !== 'pending') return res.status(400).json({ error: '该订单已被其他打手接走' });

    o.status = 'accepted';
    o.dashiId = req.user.dashiId;
    o.dashiName = req.user.name;
    writeData('orders', orders);
    return res.json(o);
});

// 打手标记完成
app.put('/api/orders/:id/complete', authMiddleware, (req, res) => {
    if (req.user.role !== 'dashi') return res.status(403).json({ error: '仅打手可操作' });

    const orders = readData('orders');
    const oid = parseInt(req.params.id);
    const o = orders.find(o => o.id === oid);
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.dashiId !== req.user.dashiId) return res.status(403).json({ error: '只能操作自己的订单' });
    if (o.status !== 'accepted') return res.status(400).json({ error: '订单状态不是进行中' });

    o.status = 'completed';

    // 更新打手完成数
    const users = readData('users');
    const dashi = users.find(u => u.dashiId === req.user.dashiId);
    if (dashi) {
        dashi.completedOrders = (dashi.completedOrders || 0) + 1;
        writeData('users', users);
    }
    writeData('orders', orders);
    return res.json(o);
});

// 顾客取消订单
app.put('/api/orders/:id/cancel', authMiddleware, (req, res) => {
    if (req.user.role !== 'guke') return res.status(403).json({ error: '仅顾客可操作' });

    const orders = readData('orders');
    const oid = parseInt(req.params.id);
    const o = orders.find(o => o.id === oid);
    if (!o) return res.status(404).json({ error: '订单不存在' });
    if (o.customerId !== req.user.id) return res.status(403).json({ error: '只能操作自己的订单' });
    if (o.status !== 'pending') return res.status(400).json({ error: '只能取消待确认的订单' });

    o.status = 'cancelled';
    writeData('orders', orders);
    return res.json(o);
});

// ============ 管理员接口 ============
app.get('/api/admin/orders', authMiddleware, adminMiddleware, (req, res) => {
    return res.json(readData('orders'));
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
    const users = readData('users');
    return res.json(users.map(u => ({ id: u.id, name: u.name, role: u.role, dashiId: u.dashiId, completedOrders: u.completedOrders || 0, createdAt: u.createdAt })));
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
        writeData('orders', []);
        writeData('tokens', []);
        return res.json({ ok: true, msg: '所有数据已清除' });
    }
    res.status(400).json({ error: '请指定 type: orders 或 all' });
});

// SPA 回退
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ error: '接口不存在' });
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log('接单平台服务已启动：http://localhost:' + PORT);
});
