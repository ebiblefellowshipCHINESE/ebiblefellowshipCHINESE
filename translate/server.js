const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer'); // 用于文件上传
const { Octokit } = require('@octokit/rest'); // GitHub API 客户端

const app = express();
const port = 3000;

// 设置视图目录和模板引擎
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// 中间件设置
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
    secret: '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',
    resave: false,
    saveUninitialized: true
}));

// 配置 multer 用于文件上传，存储到临时目录
const upload = multer({ dest: 'uploads/' });

// 配置 GitHub API 客户端
const octokit = new Octokit({
    auth: process.env.GITHUB_TOKEN || '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' // 建议使用环境变量
});

// 模拟用户数据库
const users = {
    admin: { passwordHash: bcrypt.hashSync('adminbytomliu!!!!@$', 10), role: 'admin' },
    mengxianglong: { passwordHash: bcrypt.hashSync('1', 10), role: 'translator' },
    jamesli: { passwordHash: bcrypt.hashSync('uploadbyjamesli!!!@#$%', 10), role: 'uploader' }
};

// 模拟文件数据库（实际应使用数据库如 SQLite 或 MongoDB）
let filesDB = [];

// 记录登录错误次数、访问信息和记住的设备
const loginAttempts = new Map();
const accessLogs = [];
const rememberedDevices = new Map();

// 日志记录函数
function logAttempt(ip, username, password, success, reason = '') {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] IP: ${ip}, 用户名: ${username}, 密码: ${password}, 登录${success ? '成功' : '失败'}, 原因: ${reason}\n`;
    fs.appendFileSync('login_attempts.log', logMessage);
}

// 获取祝福语
function getBlessing() {
    const hour = new Date().getHours();
    if (hour < 6) return '深夜安宁，愿神与你同在';
    if (hour < 12) return '早上好，愿你一日平安';
    if (hour < 18) return '下午愉快，愿神赐福';
    return '晚上平安，愿你安息';
}

// 生成设备 ID
function generateDeviceId() {
    return crypto.randomBytes(16).toString('hex');
}

// 登录页面 HTML
const loginHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>电子圣经团契文件翻译系统</title>
    <style>
        body {
            font-family: 'Roboto', Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #e3f2fd, #90caf9);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            overflow: hidden;
        }
        .container {
            width: 400px;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            padding: 40px;
            box-sizing: border-box;
            border: 2px solid #42a5f5;
            text-align: center;
            animation: fadeIn 1s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .logo {
            margin-bottom: 24px;
        }
        .logo img {
            width: 100px;
            height: auto;
            transition: transform 0.3s;
        }
        .logo img:hover {
            transform: scale(1.1);
        }
        h1 {
            font-size: 28px;
            font-weight: 500;
            color: #1565c0;
            margin: 0 0 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .subtitle {
            font-size: 14px;
            color: #5f6368;
            margin-bottom: 24px;
            line-height: 1.6;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            font-size: 16px;
            border: 2px solid #42a5f5;
            border-radius: 8px;
            box-sizing: border-box;
            transition: all 0.3s ease;
            background: #e3f2fd;
        }
        .form-group input:focus {
            border-color: #1976d2;
            outline: none;
            box-shadow: 0 0 10px rgba(25, 118, 210, 0.2);
        }
        .checkbox {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
        }
        .checkbox label {
            margin-left: 8px;
            color: #5f6368;
        }
        .info-text {
            font-size: 12px;
            color: #5f6368;
            margin-bottom: 24px;
            line-height: 1.6;
        }
        .actions button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(90deg, #1976d2, #1565c0);
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
        }
        .actions button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(25, 118, 210, 0.3);
        }
        .error-message {
            color: #d32f2f;
            font-size: 14px;
            margin-bottom: 20px;
            display: none;
        }
        .error-message.show {
            display: block;
        }
        .bible-verse {
            margin-top: 24px;
            font-size: 12px;
            color: #42a5f5;
            text-align: center;
            font-style: italic;
            background: rgba(66, 165, 245, 0.1);
            padding: 8px;
            border-radius: 4px;
        }
        .footer {
            position: absolute;
            bottom: 20px;
            width: 100%;
            display: flex;
            justify-content: center;
            font-size: 12px;
            color: #5f6368;
        }
        .footer select {
            border: none;
            background: transparent;
            color: #5f6368;
            margin: 0 8px;
            font-size: 12px;
        }
        .footer a {
            color: #5f6368;
            text-decoration: none;
            margin: 0 8px;
        }
        .footer a:hover {
            text-decoration: underline;
            color: #1976d2;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <img src="1.png" alt="电子圣经团契 Logo">
        </div>
        <h1>电子圣经团契<br>文件翻译系统</h1>
        <p class="subtitle">
            欢迎登录，参与圣经文件翻译与传播的圣工。
        </p>
        <div class="error-message" id="error-message"></div>
        <form action="/login" method="post" onsubmit="return handleSubmit()">
            <div class="form-group">
                <input type="text" name="username" placeholder="用户名" required>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="密码" required>
            </div>
            <div class="checkbox">
                <input type="checkbox" id="remember-device" name="remember">
                <label for="remember-device">记住此设备</label>
            </div>
            <p class="info-text">
                请确保使用安全设备登录以保护您的账户。
            </p>
            <div class="actions">
                <button type="submit">登录</button>
            </div>
        </form>
        <div class="bible-verse">
            <p>圣经经文: “神爱世人，甚至将他的独生子赐给他们。” - 约翰福音 3:16</p>
        </div>
    </div>
    <div class="footer">
        <select>
            <option>简体中文</option>
        </select>
        <a href="#">帮助</a>
        <a href="#">关于我们</a>
        <a href="#">联系方式</a>
    </div>
    <script>
        function handleSubmit() {
            document.getElementById('error-message').classList.remove('show');
            return true;
        }
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('error')) {
            const errorMessage = document.getElementById('error-message');
            errorMessage.textContent = urlParams.get('error');
            errorMessage.classList.add('show');
        }
    </script>
</body>
</html>`;

// 主页路由
app.get('/', (req, res) => {
    const ip = req.ip;
    const deviceId = req.cookies.deviceId;
    console.log(`访问IP: ${ip}, 设备ID: ${deviceId}`);

    if (deviceId && rememberedDevices.has(deviceId)) {
        const rememberedUser = rememberedDevices.get(deviceId);
        if (users[rememberedUser]) {
            req.session.user = rememberedUser;
            req.session.role = users[rememberedUser].role;
            accessLogs.push(`[${new Date().toISOString()}] IP: ${ip}, 用户名: ${rememberedUser}, 访问: / (自动登录)`);
            switch (req.session.role) {
                case 'translator':
                    return res.redirect('/translate');
                case 'admin':
                    return res.redirect('/admin');
                case 'uploader':
                    return res.redirect('/upload');
                default:
                    return res.redirect('/dashboard');
            }
        }
    }
    res.send(loginHtml);
});

// 登录处理
app.post('/login', (req, res) => {
    const { username, password, remember } = req.body || {};
    const ip = req.ip;
    let deviceId = req.cookies.deviceId || generateDeviceId();

    console.log(`登录尝试 - IP: ${ip}, 用户名: ${username || '未提供'}, 密码: ${password ? '****' : '未提供'}, 记住设备: ${remember}, 错误次数: ${loginAttempts.get(ip)?.count || 0}, req.body: ${JSON.stringify(req.body)}`);

    logAttempt(ip, username || '未提供', password || '未提供', false);
    accessLogs.push(`[${new Date().toISOString()}] IP: ${ip}, 用户名: ${username || '未提供'}, 访问: /login`);

    if (!loginAttempts.has(ip)) {
        loginAttempts.set(ip, { count: 0, timestamp: Date.now() });
    }

    const attempt = loginAttempts.get(ip);
    if (Date.now() - attempt.timestamp > 5 * 60 * 1000) {
        loginAttempts.set(ip, { count: 0, timestamp: Date.now() });
    }

    if (!username || !password) {
        logAttempt(ip, username || '未知用户', password || '未输入', false, '未提供凭据');
        return res.redirect('/?error=登录失败，请提供用户名和密码。');
    }

    if (!users[username] || !bcrypt.compareSync(password, users[username].passwordHash)) {
        attempt.count++;
        loginAttempts.set(ip, attempt);
        logAttempt(ip, username, '****', false, `错误次数: ${attempt.count}`);
        if (attempt.count >= 8) {
            loginAttempts.delete(ip);
            return res.redirect('/?error=登录失败，错误次数过多，请稍后重试。');
        } else if (attempt.count >= 5) {
            return res.redirect('/?error=登录失败，请稍后重试。');
        } else {
            return res.redirect('/?error=登录失败，请检查您的凭据。');
        }
    }

    logAttempt(ip, username, '****', true);
    req.session.user = username;
    req.session.role = users[username].role;
    loginAttempts.set(ip, { count: 0, timestamp: Date.now() });

    if (remember === 'on') {
        rememberedDevices.set(deviceId, username);
        res.cookie('deviceId', deviceId, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
    }

    switch (req.session.role) {
        case 'translator':
            return res.redirect('/translate');
        case 'admin':
            return res.redirect('/admin');
        case 'uploader':
            return res.redirect('/upload');
        default:
            return res.redirect('/dashboard');
    }
});

// 上传页面路由
app.get('/upload', (req, res) => {
    const ip = req.ip;
    if (!req.session.user || req.session.role !== 'uploader') {
        return res.redirect('/?error=未授权访问，请先登录。');
    }
    res.send(`
        <h1>文件上传页面</h1>
        <p>欢迎 ${req.session.user}，请上传文件</p>
        <form action="/upload-file" method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">上传</button>
        </form>
    `);
});

// 处理文件上传并存储到 GitHub
app.post('/upload-file', upload.single('file'), async (req, res) => {
    const ip = req.ip;
    if (!req.session.user || req.session.role !== 'uploader') {
        return res.redirect('/?error=未授权访问，请先登录。');
    }

    const file = req.file;
    if (!file) {
        return res.status(400).send('未选择文件。');
    }

    const fileContent = fs.readFileSync(file.path);
    const fileName = `${req.session.user}_${Date.now()}_${file.originalname}`;

    try {
        await octokit.repos.createOrUpdateFileContents({
            owner: 'ebiblefellowshipCHINESE', // 替换为您的 GitHub 用户名
            repo: 'ebiblefellowshipCHINESE', // 替换为您的ेलGitHub 仓库名
            path: `uploads/${fileName}`, // 文件存储路径
            message: `Upload ${fileName} by ${req.session.user}`,
            content: fileContent.toString('base64'), // 文件内容转为 base64
            branch: 'main' // 指定分支
        });
        fs.unlinkSync(file.path); // 删除临时文件

        const newFile = {
            id: crypto.randomBytes(8).toString('hex'),
            name: fileName,
            github_url: `https://raw.githubusercontent.com/ebiblefellowshipCHINESE/ebiblefellowshipCHINESE/main/uploads/${fileName}`,
            uploader: req.session.user,
            size: `${(file.size / 1024).toFixed(2)}KB`,
            upload_time: new Date().toISOString(),
            isTranslated: false,
            translator: null,
            translation_time: null,
            translated_github_url: null
        };
        filesDB.push(newFile);

        res.send('文件成功上传至 GitHub！');
    } catch (error) {
        console.error(error);
        res.status(500).send('上传文件到 GitHub 失败。');
    }
});

// 翻译页面路由（列出 GitHub 上的文件）
app.get('/translate', async (req, res) => {
    const ip = req.ip;
    if (!req.session.user || req.session.role !== 'translator') {
        return res.redirect('/?error=未授权访问，请先登录。');
    }

    try {
        const response = await octokit.repos.getContent({
            owner: 'ebiblefellowshipCHINESE',
            repo: 'ebiblefellowshipCHINESE',
            path: 'uploads'
        });

        const files = response.data.map(file => ({
            name: file.name,
            download_url: file.download_url
        }));

        res.render('translate', { username: req.session.user, files });
    } catch (error) {
        console.error(error);
        res.status(500).send('无法从 GitHub 获取文件列表。');
    }
});

// 管理员页面
app.get('/admin', (req, res) => {
    const ip = req.ip;
    if (!req.session.user || req.session.role !== 'admin') {
        return res.redirect('/?error=未授权访问，请先登录。');
    }
    const banInfo = ''; // 封禁系统已禁用
    res.render('admin', {
        blessing: getBlessing(),
        username: req.session.user,
        banInfo,
        accessLog: accessLogs.join('\n'),
        onlineUsersCount: 1 // 或其他实际统计数据
    });
});

// 退出
app.get('/logout', (req, res) => {
    const deviceId = req.cookies.deviceId;
    if (deviceId) {
        rememberedDevices.delete(deviceId);
        res.clearCookie('deviceId');
    }
    req.session.destroy();
    res.redirect('/');
});

// 获取访问日志
app.get('/get-access-log', (req, res) => {
    res.json(accessLogs);
});

// 修改密码
app.post('/update-password', (req, res) => {
    const { username, newPassword } = req.body;
    if (users[username]) {
        users[username].passwordHash = bcrypt.hashSync(newPassword, 10);
        res.send('密码修改成功。');
    } else {
        res.send('用户不存在。');
    }
});

// 创建账号
app.post('/create-account', (req, res) => {
    const { username, password, role } = req.body;
    if (!users[username]) {
        users[username] = {
            passwordHash: bcrypt.hashSync(password, 10),
            role: role
        };
        res.send('账号创建成功。');
    } else {
        res.send('用户名已存在。');
    }
});

// 仪表板页面
app.get('/dashboard', (req, res) => {
    const ip = req.ip;
    if (!req.session.user) {
        return res.redirect('/?error=未授权访问，请先登录。');
    }
    res.send(`欢迎 ${req.session.user}，您的角色是 ${req.session.role}`);
});

// 未授权访问的处理
app.use((req, res) => {
    res.redirect('/?error=未授权访问，请先登录。');
});

app.listen(port, () => {
    console.log(`服务器运行于 http://localhost:${port}`);
});

// 新增增强型路由，支持完整模板功能并修复 role 未定义问题
app.get('/dashboard-enhanced', async (req, res) => {
    const ip = req.ip;
    if (!req.session.user) {
        return res.redirect('/?error=未授权访问，请先登录。');
    }

    try {
        const response = await octokit.repos.getContent({
            owner: 'ebiblefellowshipCHINESE',
            repo: 'ebiblefellowshipCHINESE',
            path: 'uploads'
        });

        const files = response.data.map(file => {
            const existingFile = filesDB.find(f => f.name === file.name) || {};
            return {
                id: crypto.randomBytes(8).toString('hex'),
                name: file.name,
                github_url: file.download_url,
                uploader: existingFile.uploader || req.session.user,
                size: file.size ? `${(file.size / 1024).toFixed(2)}KB` : '未知',
                upload_time: existingFile.upload_time || new Date().toISOString(),
                isTranslated: existingFile.isTranslated || file.name.includes('_translated'),
                translator: existingFile.translator || null,
                translation_time: existingFile.translation_time || null,
                translated_github_url: existingFile.translated_github_url || null
            };
        });

        filesDB = files; // 更新内存中的文件数据库

        const myFiles = files.filter(f => f.name.includes(req.session.user));
        const sharedFiles = files.filter(f => !f.name.includes(req.session.user));

        res.render('translate-enhanced', {
            username: req.session.user,
            role: req.session.role, // 传递 role
            files: files,
            myFiles: myFiles,
            sharedFiles: sharedFiles
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('无法从 GitHub 获取文件列表。');
    }
});

// 新增增强型登录路由，重定向到 dashboard-enhanced
app.post('/login-enhanced', (req, res) => {
    const { username, password, remember } = req.body || {};
    const ip = req.ip;
    let deviceId = req.cookies.deviceId || generateDeviceId();

    console.log(`登录尝试 - IP: ${ip}, 用户名: ${username || '未提供'}, 密码: ${password ? '****' : '未提供'}, 记住设备: ${remember}, 错误次数: ${loginAttempts.get(ip)?.count || 0}, req.body: ${JSON.stringify(req.body)}`);

    logAttempt(ip, username || '未提供', password || '未提供', false);
    accessLogs.push(`[${new Date().toISOString()}] IP: ${ip}, 用户名: ${username || '未提供'}, 访问: /login-enhanced`);

    if (!loginAttempts.has(ip)) {
        loginAttempts.set(ip, { count: 0, timestamp: Date.now() });
    }

    const attempt = loginAttempts.get(ip);
    if (Date.now() - attempt.timestamp > 5 * 60 * 1000) {
        loginAttempts.set(ip, { count: 0, timestamp: Date.now() });
    }

    if (!username || !password) {
        logAttempt(ip, username || '未知用户', password || '未输入', false, '未提供凭据');
        return res.redirect('/?error=登录失败，请提供用户名和密码。');
    }

    if (!users[username] || !bcrypt.compareSync(password, users[username].passwordHash)) {
        attempt.count++;
        loginAttempts.set(ip, attempt);
        logAttempt(ip, username, '****', false, `错误次数: ${attempt.count}`);
        if (attempt.count >= 8) {
            loginAttempts.delete(ip);
            return res.redirect('/?error=登录失败，错误次数过多，请稍后重试。');
        } else if (attempt.count >= 5) {
            return res.redirect('/?error=登录失败，请稍后重试。');
        } else {
            return res.redirect('/?error=登录失败，请检查您的凭据。');
        }
    }

    logAttempt(ip, username, '****', true);
    req.session.user = username;
    req.session.role = users[username].role;
    loginAttempts.set(ip, { count: 0, timestamp: Date.now() });

    if (remember === 'on') {
        rememberedDevices.set(deviceId, username);
        res.cookie('deviceId', deviceId, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
    }

    switch (req.session.role) {
        case 'translator':
            return res.redirect('/dashboard-enhanced');
        case 'admin':
            return res.redirect('/admin');
        case 'uploader':
            return res.redirect('/dashboard-enhanced');
        default:
            return res.redirect('/dashboard');
    }
});

// 新增增强型文件上传路由
app.post('/upload-file-enhanced', upload.single('file'), async (req, res) => {
    const ip = req.ip;
    if (!req.session.user) {
        return res.status(401).json({ success: false, error: '未授权，请先登录' });
    }

    const file = req.file;
    if (!file) {
        return res.status(400).json({ success: false, error: '未选择文件' });
    }

    const fileContent = fs.readFileSync(file.path);
    const fileName = `${req.session.user}_${Date.now()}_${file.originalname}`;

    try {
        await octokit.repos.createOrUpdateFileContents({
            owner: 'ebiblefellowshipCHINESE',
            repo: 'ebiblefellowshipCHINESE',
            path: `uploads/${fileName}`,
            message: `Upload ${fileName} by ${req.session.user}`,
            content: fileContent.toString('base64'),
            branch: 'main'
        });

        fs.unlinkSync(file.path);

        const newFile = {
            id: crypto.randomBytes(8).toString('hex'),
            name: fileName,
            github_url: `https://raw.githubusercontent.com/ebiblefellowshipCHINESE/ebiblefellowshipCHINESE/main/uploads/${fileName}`,
            uploader: req.session.user,
            size: `${(file.size / 1024).toFixed(2)}KB`,
            upload_time: new Date().toISOString(),
            isTranslated: false,
            translator: null,
            translation_time: null,
            translated_github_url: null
        };
        filesDB.push(newFile);

        res.json({
            success: true,
            download_url: newFile.github_url
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: '上传文件到 GitHub 失败' });
    }
});

// 新增建议提交路由
app.post('/submit-suggestion', (req, res) => {
    const { filename, suggestion } = req.body;
    if (!req.session.user) {
        return res.status(401).json({ success: false, error: '未授权，请先登录' });
    }
    if (!filename || !suggestion) {
        return res.status(400).json({ success: false, error: '文件名或建议内容缺失' });
    }
    console.log(`建议已记录: 文件 ${filename}, 建议 ${suggestion}, 用户 ${req.session.user}`);
    res.json({ success: true });
});

// 新增增强型主页，使用 EJS 模板
app.get('/login-enhanced-page', (req, res) => {
    const ip = req.ip;
    const deviceId = req.cookies.deviceId;
    console.log(`访问IP: ${ip}, 设备ID: ${deviceId}`);

    if (deviceId && rememberedDevices.has(deviceId)) {
        const rememberedUser = rememberedDevices.get(deviceId);
        if (users[rememberedUser]) {
            req.session.user = rememberedUser;
            req.session.role = users[rememberedUser].role;
            accessLogs.push(`[${new Date().toISOString()}] IP: ${ip}, 用户名: ${rememberedUser}, 访问: /login-enhanced-page (自动登录)`);
            switch (req.session.role) {
                case 'translator':
                    return res.redirect('/dashboard-enhanced');
                case 'admin':
                    return res.redirect('/admin');
                case 'uploader':
                    return res.redirect('/dashboard-enhanced');
                default:
                    return res.redirect('/dashboard');
            }
        }
    }
    res.render('login', { error: req.query.error });
});

// 新增翻译文件上传路由
app.post('/upload-translation', upload.single('translation'), async (req, res) => {
    const ip = req.ip;
    if (!req.session.user || req.session.role !== 'translator') {
        return res.status(401).json({ success: false, error: '未授权，请先登录' });
    }

    const { file_id } = req.body;
    const file = req.file;
    if (!file || !file_id) {
        return res.status(400).json({ success: false, error: '未选择文件或缺少文件ID' });
    }

    const targetFile = filesDB.find(f => f.id === file_id);
    if (!targetFile) {
        return res.status(404).json({ success: false, error: '文件未找到' });
    }

    const fileContent = fs.readFileSync(file.path);
    const translatedFileName = `${targetFile.name.split('.')[0]}_translated_${Date.now()}.${file.originalname.split('.').pop()}`;

    try {
        await octokit.repos.createOrUpdateFileContents({
            owner: 'ebiblefellowshipCHINESE',
            repo: 'ebiblefellowshipCHINESE',
            path: `uploads/${translatedFileName}`,
            message: `Translation of ${targetFile.name} by ${req.session.user}`,
            content: fileContent.toString('base64'),
            branch: 'main'
        });

        fs.unlinkSync(file.path);

        targetFile.isTranslated = true;
        targetFile.translator = req.session.user;
        targetFile.translation_time = new Date().toISOString();
        targetFile.translated_github_url = `https://raw.githubusercontent.com/ebiblefellowshipCHINESE/ebiblefellowshipCHINESE/main/uploads/${translatedFileName}`;

        res.json({ success: true, file: targetFile });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: '上传翻译文件到 GitHub 失败' });
    }
});