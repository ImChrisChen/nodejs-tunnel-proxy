import { HTTPSMITMProxy } from "./main.js";
// const mitmProxy = new HTTPSMITMProxy({
//   port: 8888,
//   caKeyPath: '/Users/chris/.proxycast/certs/root-ca.key',    // CA 私钥路径
//   caCertPath: '/Users/chris/.proxycast/certs/root-ca.crt',   // CA 证书路径
//   downstreamProxy: {
//     host: '127.0.0.1',
//     port: 7890 // 指向另一个代理
//   }
// });
// mitmProxy.start();
import fs from 'node:fs'

const logger = new HTTPSMITMProxy({
  port: 8888,
  caKeyPath: '/Users/chris/.proxycast/certs/root-ca.key',
  caCertPath: '/Users/chris/.proxycast/certs/root-ca.crt',
  downstreamProxy: {
    type: 'socks5',
    host: '127.0.0.1',
    port: 7890
  }
});

// 创建日志文件
const logStream = fs.createWriteStream('traffic.log', { flags: 'a' });

logger
  .on('onConnect', (context) => {
    const timestamp = new Date().toISOString();
    logStream.write(`\n[${timestamp}] === 新连接: ${context.hostname} ===\n`);
  })
  .on('onRequest', (context) => {
    const timestamp = new Date().toISOString();
    const protocol = context.getMetadata('protocol') || 'unknown';

    logStream.write(`[${timestamp}] 请求 [${protocol}]:\n`);
    logStream.write(`  ${context.request.method} ${context.request.path}\n`);
    logStream.write(`  Headers: ${JSON.stringify(context.request.headers, null, 2)}\n`);

    // 阻止某些请求
    if (context.request.path.includes('/ads/')) {
      console.log('[钩子] 阻止广告请求');
      context.request.raw = 'GET /404 HTTP/1.1\r\n\r\n';
    }
  })
  .on('onResponse', (context) => {
    const timestamp = new Date().toISOString();

    logStream.write(`[${timestamp}] 响应:\n`);
    logStream.write(`  ${context.response.statusCode} ${context.response.statusMessage}\n`);
    logStream.write(`  Content-Type: ${context.response.headers['content-type'] || 'N/A'}\n`);

    // 修改响应内容
    if (context.response.headers['content-type']?.includes('application/json')) {
      try {
        const bodyStart = context.response.raw.indexOf('\r\n\r\n') + 4;
        const body = context.response.raw.substring(bodyStart);
        const json = JSON.parse(body);

        // 修改 JSON 数据
        json._mitm_timestamp = new Date().toISOString();

        const newBody = JSON.stringify(json);
        context.response.raw = context.response.raw.substring(0, bodyStart) + newBody;

        console.log('[钩子] JSON 响应已修改');
      } catch (e) {
        // 解析失败，忽略
      }
    }
  })
  .on('onError', (context, error) => {
    const timestamp = new Date().toISOString();
    logStream.write(`[${timestamp}] 错误: ${error.message}\n`);
  })
  .on('onClose', (context) => {
    const timestamp = new Date().toISOString();
    logStream.write(`[${timestamp}] === 连接关闭: ${context.hostname} ===\n\n`);
  });

logger.start();

// 优雅关闭
process.on('SIGINT', () => {
  console.log('\n正在关闭代理...');
  logger.stop();
  logStream.end();
  process.exit(0);
});