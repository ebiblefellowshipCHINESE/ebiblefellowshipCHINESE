const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// 中间件：解析 JSON 请求体
app.use(express.json());

// 示例路由
app.get('/', (req, res) => {
  res.json({ message: 'Hello from Node.js backend!' });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
