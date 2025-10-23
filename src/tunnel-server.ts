import net from 'net';
import http from 'http';

// 端口定义
const TUNNEL_PORT = 9000; // 用于客户端连接的隧道端口
const PUBLIC_PORT = 8080; // 对外暴露的公网端口

let tunnelSocket: net.Socket | null = null; // 存储与内网客户端建立的隧道连接

// --- 步骤 1: 监听隧道端口 (接收内网客户端连接) ---
const tunnelServer = net.createServer((socket) => {
  console.log('【隧道】内网客户端已连接，隧道建立成功。');
  tunnelSocket = socket;

  // 如果客户端断开，清空隧道引用
  socket.on('end', () => {
    console.log('【隧道】内网客户端断开。');
    tunnelSocket = null;
  });

  socket.on('error', (err) => {
    console.error('【隧道错误】', err.message);
    tunnelSocket = null;
  });

  // 在这个简单实现中，服务端不需要处理来自隧道的数据，因为数据流是公网请求 -> 隧道 -> 客户端。
});

tunnelServer.listen(TUNNEL_PORT, () => {
  console.log(`【服务端】隧道监听在端口 ${TUNNEL_PORT}`);
});

// --- 步骤 2: 监听公网请求端口 ---
const httpServer = http.createServer((req, res) => {
  const rawData: Buffer[] = [];
  req.on('data', (chunk) => {
    rawData.push(chunk);
  });

  req.on('end', () => {
    if (!tunnelSocket) {
      console.log('【公网】无活动隧道，拒绝请求。');
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      res.end('Tunnel not active (Service Unavailable)');
      return;
    }

    // --- 步骤 3: 通过隧道转发请求 ---
    // 核心逻辑：将公网请求的原始数据（包括HTTP头和体）发送给隧道
    // 注意：这里需要确保将HTTP请求的起始行和头部信息也包含进去
    const requestData = Buffer.concat([
      Buffer.from(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`),
      Buffer.from(Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n\r\n'),
      ...rawData
    ]);

    // 实际应用中，还需要一个机制将公网请求和内网响应对应起来，
    // 这里只是简单地把请求发过去。
    tunnelSocket.write(requestData);

    // **简化处理：** 在真实场景中，服务端需要等待客户端通过隧道返回响应数据，
    // 然后再发送给公网用户。但在 PoC 中，我们只演示请求的转发，并立刻返回一个占位响应。
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Request forwarded to internal network (PoC)');
  });
});

httpServer.listen(PUBLIC_PORT, () => {
  console.log(`【服务端】公网 HTTP 监听在端口 ${PUBLIC_PORT}`);
});