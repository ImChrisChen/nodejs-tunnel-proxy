import net from 'net';
import tls from 'tls';
import http from 'http';
import http2 from 'http2';
import url from 'url';
import fs from 'fs';
import crypto from 'crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/**
 * 代理上下文 - 用于在钩子之间传递和修改数据
 */
class ProxyContext {
  constructor(hostname, port) {
    this.hostname = hostname;
    this.port = port;
    this.clientSocket = null;
    this.serverSocket = null;
    this.metadata = {};
  }

  // 请求数据
  request = {
    method: null,
    path: null,
    headers: {},
    body: null,
    raw: null
  };

  // 响应数据
  response = {
    statusCode: null,
    statusMessage: null,
    headers: {},
    body: null,
    raw: null
  };

  // 设置元数据
  setMetadata(key, value) {
    this.metadata[key] = value;
  }

  // 获取元数据
  getMetadata(key) {
    return this.metadata[key];
  }
}

/**
 * SOCKS5 客户端实现
 */
class Socks5Client {
  /**
   * 通过 SOCKS5 代理建立连接
   * @param {Object} proxyConfig - { host, port, auth: 'user:pass' }
   * @param {string} targetHost - 目标主机
   * @param {number} targetPort - 目标端口
   * @returns {Promise<net.Socket>}
   */
  static async connect(proxyConfig, targetHost, targetPort) {
    return new Promise((resolve, reject) => {
      console.log(`[SOCKS5] 连接到 SOCKS5 代理 ${proxyConfig.host}:${proxyConfig.port}`);

      const socket = net.connect({
        host: proxyConfig.host,
        port: proxyConfig.port,
        timeout: 10000
      });

      let step = 'connecting';

      socket.on('connect', async () => {
        console.log('[SOCKS5] TCP 连接建立');

        try {
          // 步骤 1: 发送认证方法协商
          await Socks5Client.negotiateAuth(socket, proxyConfig.auth);

          // 步骤 2: 发送连接请求
          await Socks5Client.sendConnectRequest(socket, targetHost, targetPort);

          console.log(`[SOCKS5] 成功建立到 ${targetHost}:${targetPort} 的连接`);
          resolve(socket);
        } catch (error) {
          socket.destroy();
          reject(error);
        }
      });

      socket.on('error', (err) => {
        console.error(`[SOCKS5] 错误 (${step}):`, err.message);
        reject(err);
      });

      socket.on('timeout', () => {
        console.error('[SOCKS5] 连接超时');
        socket.destroy();
        reject(new Error('SOCKS5 connection timeout'));
      });
    });
  }

  /**
   * 协商认证方法
   */
  static async negotiateAuth(socket, auth) {
    return new Promise((resolve, reject) => {
      // 支持的认证方法
      const methods = auth ? [0x00, 0x02] : [0x00]; // 0x00=无认证, 0x02=用户名/密码
      const authRequest = Buffer.from([
        0x05, // SOCKS 版本
        methods.length, // 方法数量
        ...methods
      ]);

      socket.write(authRequest);

      socket.once('data', async (data) => {
        if (data[0] !== 0x05) {
          reject(new Error('Invalid SOCKS version'));
          return;
        }

        const method = data[1];
        console.log(`[SOCKS5] 认证方法: 0x${method.toString(16)}`);

        if (method === 0x00) {
          // 无需认证
          resolve();
        } else if (method === 0x02 && auth) {
          // 用户名/密码认证
          try {
            await Socks5Client.authenticate(socket, auth);
            resolve();
          } catch (error) {
            reject(error);
          }
        } else if (method === 0xFF) {
          reject(new Error('No acceptable authentication method'));
        } else {
          reject(new Error(`Unsupported authentication method: 0x${method.toString(16)}`));
        }
      });
    });
  }

  /**
   * 用户名/密码认证
   */
  static async authenticate(socket, auth) {
    return new Promise((resolve, reject) => {
      const [username, password] = auth.split(':');
      const authData = Buffer.concat([
        Buffer.from([0x01]), // 认证版本
        Buffer.from([username.length]),
        Buffer.from(username),
        Buffer.from([password.length]),
        Buffer.from(password)
      ]);

      socket.write(authData);

      socket.once('data', (data) => {
        if (data[0] !== 0x01) {
          reject(new Error('Invalid auth version'));
          return;
        }

        if (data[1] === 0x00) {
          console.log('[SOCKS5] 认证成功');
          resolve();
        } else {
          reject(new Error('Authentication failed'));
        }
      });
    });
  }

  /**
   * 发送连接请求
   */
  static async sendConnectRequest(socket, targetHost, targetPort) {
    return new Promise((resolve, reject) => {
      // 构造连接请求
      const hostBuffer = Buffer.from(targetHost);
      const request = Buffer.concat([
        Buffer.from([
          0x05, // SOCKS 版本
          0x01, // CONNECT 命令
          0x00, // 保留字节
          0x03, // 地址类型: 域名
          hostBuffer.length // 域名长度
        ]),
        hostBuffer,
        Buffer.from([
          (targetPort >> 8) & 0xFF, // 端口高字节
          targetPort & 0xFF // 端口低字节
        ])
      ]);

      socket.write(request);

      socket.once('data', (data) => {
        if (data[0] !== 0x05) {
          reject(new Error('Invalid SOCKS version in response'));
          return;
        }

        const reply = data[1];
        if (reply === 0x00) {
          console.log('[SOCKS5] 连接请求成功');
          resolve();
        } else {
          const errors = {
            0x01: 'General SOCKS server failure',
            0x02: 'Connection not allowed by ruleset',
            0x03: 'Network unreachable',
            0x04: 'Host unreachable',
            0x05: 'Connection refused',
            0x06: 'TTL expired',
            0x07: 'Command not supported',
            0x08: 'Address type not supported'
          };
          reject(new Error(errors[reply] || `SOCKS error: 0x${reply.toString(16)}`));
        }
      });
    });
  }
}

/**
 * HTTP/2 客户端实现
 */
class HTTP2Client {
  /**
   * 通过已有的 TLS socket 创建 HTTP/2 会话
   */
  static createSession(tlsSocket, authority) {
    return new Promise((resolve, reject) => {
      console.log('[HTTP/2] 创建 HTTP/2 会话');

      const client = http2.connect(authority, {
        createConnection: () => tlsSocket,
        settings: {
          enablePush: false
        }
      });

      client.on('connect', () => {
        console.log('[HTTP/2] HTTP/2 会话建立成功');
        resolve(client);
      });

      client.on('error', (err) => {
        console.error('[HTTP/2] 会话错误:', err.message);
        reject(err);
      });
    });
  }

  /**
   * 发送 HTTP/2 请求
   */
  static sendRequest(client, method, path, headers) {
    return new Promise((resolve, reject) => {
      const reqHeaders = {
        ':method': method,
        ':path': path,
        ...headers
      };

      console.log(`[HTTP/2] 发送 ${method} 请求: ${path}`);

      const req = client.request(reqHeaders);

      let responseHeaders = null;
      let responseData = '';

      req.on('response', (headers) => {
        responseHeaders = headers;
        console.log('[HTTP/2] 收到响应头:', headers[':status']);
      });

      req.on('data', (chunk) => {
        responseData += chunk.toString();
      });

      req.on('end', () => {
        console.log('[HTTP/2] 响应接收完成');
        resolve({
          statusCode: parseInt(responseHeaders[':status']),
          headers: responseHeaders,
          body: responseData
        });
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.end();
    });
  }
}

/**
 * HTTPS 请求客户端（支持 HTTP/1.1, HTTP/2, SOCKS5）
 */
class HTTPSProxyRequest {
  constructor(targetUrl, proxyConfig = null) {
    this.targetUrl = url.parse(targetUrl);
    this.proxy = proxyConfig;
    this.useProxy = !!proxyConfig;
    this.socket = null;
    this.tlsSocket = null;
    this.http2Client = null;
    this.protocol = 'http/1.1'; // 默认协议
  }

  /**
   * 建立 TCP 连接（支持 HTTP/HTTPS/SOCKS5 代理）
   */
  async connect() {
    if (!this.useProxy) {
      // 直连
      return this.connectDirect();
    }

    if (this.proxy.type === 'socks5') {
      // SOCKS5 代理
      return this.connectViaSocks5();
    } else {
      // HTTP/HTTPS 代理
      return this.connectViaHttpProxy();
    }
  }

  /**
   * 直接连接
   */
  connectDirect() {
    return new Promise((resolve, reject) => {
      const targetHost = this.targetUrl.hostname;
      const targetPort = this.targetUrl.port || 443;
      console.log(`[TCP] 直接连接 ${targetHost}:${targetPort}`);

      this.socket = net.connect({
        host: targetHost,
        port: targetPort,
        timeout: 10000
      });

      this.socket.on('connect', () => {
        console.log('[TCP] 连接成功');
        resolve();
      });

      this.socket.on('error', reject);
      this.socket.on('timeout', () => {
        this.socket.destroy();
        reject(new Error('Connection timeout'));
      });
    });
  }

  /**
   * 通过 SOCKS5 代理连接
   */
  async connectViaSocks5() {
    const targetHost = this.targetUrl.hostname;
    const targetPort = this.targetUrl.port || 443;

    this.socket = await Socks5Client.connect(
      this.proxy,
      targetHost,
      targetPort
    );
  }

  /**
   * 通过 HTTP/HTTPS 代理连接
   */
  async connectViaHttpProxy() {
    return new Promise((resolve, reject) => {
      console.log(`[HTTP Proxy] 连接到代理 ${this.proxy.host}:${this.proxy.port}`);

      this.socket = net.connect({
        host: this.proxy.host,
        port: this.proxy.port,
        timeout: 10000
      });

      this.socket.on('connect', async () => {
        console.log('[HTTP Proxy] TCP 连接成功');
        await this.establishHttpTunnel();
        resolve();
      });

      this.socket.on('error', reject);
      this.socket.on('timeout', () => {
        this.socket.destroy();
        reject(new Error('Proxy connection timeout'));
      });
    });
  }

  /**
   * 建立 HTTP CONNECT 隧道
   */
  establishHttpTunnel() {
    return new Promise((resolve, reject) => {
      const target = `${this.targetUrl.hostname}:${this.targetUrl.port || 443}`;
      let connectRequest = `CONNECT ${target} HTTP/1.1\r\n`;
      connectRequest += `Host: ${target}\r\n`;

      if (this.proxy.auth) {
        const auth = Buffer.from(this.proxy.auth).toString('base64');
        connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
      }

      connectRequest += `\r\n`;

      let responseData = '';
      const onData = (data) => {
        responseData += data.toString();

        if (responseData.includes('\r\n\r\n')) {
          this.socket.removeListener('data', onData);
          const statusCode = parseInt(responseData.split(' ')[1]);

          if (statusCode === 200) {
            console.log('[HTTP Proxy] 隧道建立成功');
            resolve();
          } else {
            reject(new Error(`Proxy returned ${statusCode}`));
          }
        }
      };

      this.socket.on('data', onData);
      this.socket.write(connectRequest);
    });
  }

  /**
   * TLS 握手（支持 ALPN 协议协商）
   */
  performTLSHandshake(preferHttp2 = true) {
    return new Promise((resolve, reject) => {
      console.log('[TLS] 开始 TLS 握手');

      const tlsOptions = {
        socket: this.socket,
        servername: this.targetUrl.hostname,
        rejectUnauthorized: false
      };

      // 支持 ALPN 协议协商
      if (preferHttp2) {
        tlsOptions.ALPNProtocols = ['h2', 'http/1.1'];
      }

      this.tlsSocket = tls.connect(tlsOptions);

      this.tlsSocket.on('secureConnect', () => {
        this.protocol = this.tlsSocket.alpnProtocol || 'http/1.1';
        console.log('[TLS] TLS 握手成功');
        console.log('[TLS] 协商协议:', this.protocol);
        console.log('[TLS] 加密套件:', this.tlsSocket.getCipher().name);
        resolve();
      });

      this.tlsSocket.on('error', reject);
    });
  }

  /**
   * 发送 HTTP 请求（自动选择 HTTP/1.1 或 HTTP/2，支持回退）
   */
  async sendRequest(method = 'GET', path = '/', headers = {}) {
    if (this.protocol === 'h2') {
      try {
        return await this.sendHttp2Request(method, path, headers);
      } catch (error) {
        console.warn('[HTTP/2] 请求失败，回退到 HTTP/1.1:', error.message);
        this.protocol = 'http/1.1';
        return await this.sendHttp1Request(method, path, headers);
      }
    } else {
      return await this.sendHttp1Request(method, path, headers);
    }
  }

  /**
   * 发送 HTTP/2 请求
   */
  async sendHttp2Request(method, path, headers) {
    const authority = `https://${this.targetUrl.hostname}`;

    try {
      this.http2Client = await HTTP2Client.createSession(this.tlsSocket, authority);

      const reqHeaders = {
        ':authority': this.targetUrl.hostname,
        'user-agent': 'Node.js HTTP/2 Client',
        ...headers
      };

      return await HTTP2Client.sendRequest(this.http2Client, method, path, reqHeaders);
    } catch (error) {
      // HTTP/2 失败，抛出错误以便上层回退
      throw new Error(`HTTP/2 request failed: ${error.message}`);
    }
  }

  /**
   * 发送 HTTP/1.1 请求
   */
  sendHttp1Request(method, path, headers) {
    return new Promise((resolve, reject) => {
      console.log(`[HTTP/1.1] 发送 ${method} 请求`);

      const requestOptions = {
        method: method,
        path: path || '/',
        headers: {
          'Host': this.targetUrl.hostname,
          'User-Agent': 'Node.js HTTP/1.1 Client',
          'Connection': 'close',
          ...headers
        },
        createConnection: () => this.tlsSocket
      };

      const req = http.request(requestOptions, (res) => {
        console.log(`[HTTP/1.1] 收到响应: ${res.statusCode}`);

        let responseData = '';
        res.on('data', (chunk) => {
          responseData += chunk.toString();
        });

        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            body: responseData
          });
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  /**
   * 完整请求流程
   */
  async request(method = 'GET', path = '/', headers = {}, preferHttp2 = true) {
    try {
      await this.connect();
      await this.performTLSHandshake(preferHttp2);
      const result = await this.sendRequest(method, path, headers);
      return result;
    } finally {
      this.close();
    }
  }

  /**
   * 关闭连接
   */
  close() {
    if (this.http2Client) {
      this.http2Client.close();
    }
    if (this.tlsSocket) {
      this.tlsSocket.end();
    }
    if (this.socket) {
      this.socket.end();
    }
  }
}

/**
 * HTTPS 中间人代理（支持钩子、SOCKS5、HTTP/2）
 */
class HTTPSMITMProxy {
  constructor(config) {
    this.port = config.port || 8888;
    this.caKeyPath = config.caKeyPath;
    this.caCertPath = config.caCertPath;
    this.caKey = null;
    this.caCert = null;
    this.certCache = new Map();
    this.server = null;
    this.downstreamProxy = config.downstreamProxy || null;

    // 钩子函数
    this.hooks = {
      onConnect: null,        // (context) => {}
      onRequest: null,        // (context) => {}
      onResponse: null,       // (context) => {}
      onError: null,          // (context, error) => {}
      onClose: null           // (context) => {}
    };

    this.loadCA();
  }

  /**
   * 注册钩子
   */
  on(event, handler) {
    if (this.hooks.hasOwnProperty(event)) {
      this.hooks[event] = handler;
    } else {
      throw new Error(`Unknown hook: ${event}`);
    }
    return this;
  }

  /**
   * 触发钩子
   */
  async triggerHook(event, ...args) {
    if (this.hooks[event]) {
      try {
        await this.hooks[event](...args);
      } catch (error) {
        console.error(`[Hook Error] ${event}:`, error.message);
      }
    }
  }

  loadCA() {
    try {
      this.caKey = fs.readFileSync(this.caKeyPath, 'utf8');
      this.caCert = fs.readFileSync(this.caCertPath, 'utf8');
      console.log('[CA] 证书加载成功');
    } catch (error) {
      throw new Error(`加载 CA 证书失败: ${error.message}`);
    }
  }

  generateCertificate(hostname) {
    if (this.certCache.has(hostname)) {
      return this.certCache.get(hostname);
    }

    console.log(`[证书] 为 ${hostname} 生成证书`);

    const keys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const cert = this.createCertificate(hostname, keys.publicKey, keys.privateKey);
    const certPair = { key: keys.privateKey, cert: cert };

    this.certCache.set(hostname, certPair);
    return certPair;
  }

  createCertificate(hostname, publicKey, privateKey) {
    const pki = require('node-forge').pki;
    const cert = pki.createCertificate();

    cert.publicKey = pki.publicKeyFromPem(publicKey);
    cert.serialNumber = '01' + Date.now().toString(16);

    const now = new Date();
    cert.validity.notBefore = now;
    cert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

    cert.setSubject([{
      name: 'commonName',
      value: hostname
    }]);

    const caCert = pki.certificateFromPem(this.caCert);
    cert.setIssuer(caCert.subject.attributes);

    cert.setExtensions([{
      name: 'subjectAltName',
      altNames: [{ type: 2, value: hostname }]
    }]);

    const caKey = pki.privateKeyFromPem(this.caKey);
    cert.sign(caKey, require('node-forge').md.sha256.create());

    return pki.certificateToPem(cert);
  }

  handleConnection(clientSocket) {
    console.log('\n[新连接] 客户端连接');

    clientSocket.once('data', (data) => {
      const requestData = data.toString();
      const lines = requestData.split('\r\n');
      const [method, targetUrl] = lines[0].split(' ');

      if (method === 'CONNECT') {
        this.handleHTTPSRequest(clientSocket, targetUrl);
      } else {
        clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      }
    });

    clientSocket.on('error', (err) => {
      console.error('[客户端错误]', err.message);
    });
  }

  async handleHTTPSRequest(clientSocket, target) {
    const [hostname, port] = target.split(':');
    const context = new ProxyContext(hostname, port || 443);
    context.clientSocket = clientSocket;

    console.log(`\n[HTTPS] 拦截 ${hostname}:${port || 443}`);

    try {
      // 触发连接钩子
      await this.triggerHook('onConnect', context);

      // 向客户端返回 200
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

      // 生成伪造证书
      const certPair = this.generateCertificate(hostname);

      // 升级客户端连接为 TLS
      const clientTLSSocket = new tls.TLSSocket(clientSocket, {
        isServer: true,
        key: certPair.key,
        cert: certPair.cert,
        ALPNProtocols: ['h2', 'http/1.1'],
        SNICallback: (servername, cb) => {
          const cert = this.generateCertificate(servername);
          cb(null, tls.createSecureContext({
            key: cert.key,
            cert: cert.cert
          }));
        }
      });

      // 连接到目标服务器
      await this.connectToTarget(clientTLSSocket, context, hostname, port || 443);

    } catch (error) {
      console.error('[HTTPS 错误]', error.message);
      await this.triggerHook('onError', context, error);
      clientSocket.end();
    }
  }

  async connectToTarget(clientTLSSocket, context, hostname, port) {
    let serverSocket;

    // 根据下游代理类型选择连接方式
    if (this.downstreamProxy) {
      if (this.downstreamProxy.type === 'socks5') {
        console.log('[下游代理] 使用 SOCKS5');
        serverSocket = await Socks5Client.connect(
          this.downstreamProxy,
          hostname,
          port
        );
      } else {
        console.log('[下游代理] 使用 HTTP 代理');
        serverSocket = await this.connectViaHttpProxy(hostname, port);
      }
    } else {
      console.log('[直连] 连接目标服务器');
      serverSocket = await this.connectDirect(hostname, port);
    }

    context.serverSocket = serverSocket;

    // TLS 握手
    const serverTLSSocket = await this.performServerTLS(serverSocket, hostname);

    // 检测协议
    const protocol = clientTLSSocket.alpnProtocol || 'http/1.1';
    context.setMetadata('protocol', protocol);
    console.log(`[协议] 客户端协商: ${protocol}`);

    // 拦截并转发
    await this.interceptAndForward(clientTLSSocket, serverTLSSocket, context);
  }

  connectDirect(hostname, port) {
    return new Promise((resolve, reject) => {
      const socket = net.connect({ host: hostname, port });
      socket.on('connect', () => resolve(socket));
      socket.on('error', reject);
    });
  }

  async connectViaHttpProxy(hostname, port) {
    return new Promise((resolve, reject) => {
      const socket = net.connect({
        host: this.downstreamProxy.host,
        port: this.downstreamProxy.port
      });

      socket.on('connect', async () => {
        const target = `${hostname}:${port}`;
        let request = `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n`;

        if (this.downstreamProxy.auth) {
          const auth = Buffer.from(this.downstreamProxy.auth).toString('base64');
          request += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        request += '\r\n';

        let response = '';
        const onData = (data) => {
          response += data.toString();
          if (response.includes('\r\n\r\n')) {
            socket.removeListener('data', onData);
            const statusCode = parseInt(response.split(' ')[1]);
            if (statusCode === 200) {
              resolve(socket);
            } else {
              reject(new Error(`Proxy error: ${statusCode}`));
            }
          }
        };

        socket.on('data', onData);
        socket.write(request);
      });

      socket.on('error', reject);
    });
  }

  performServerTLS(socket, hostname) {
    return new Promise((resolve, reject) => {
      const tlsSocket = tls.connect({
        socket: socket,
        servername: hostname,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1']
      });

      tlsSocket.on('secureConnect', () => {
        console.log('[TLS] 服务器 TLS 握手完成');
        resolve(tlsSocket);
      });

      tlsSocket.on('error', reject);
    });
  }

  async interceptAndForward(clientTLS, serverTLS, context) {
    console.log(`[拦截] 开始拦截 ${context.hostname}`);

    // 客户端 -> 服务器
    clientTLS.on('data', async (data) => {
      const dataStr = data.toString();

      // 解析 HTTP 请求
      if (dataStr.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)/)) {
        console.log('\n========== 请求 ==========');
        const lines = dataStr.split('\r\n');
        const [method, path] = lines[0].split(' ');

        context.request.method = method;
        context.request.path = path;
        context.request.raw = dataStr;

        // 解析请求头
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i];
          if (line === '') break;
          const [key, ...valueParts] = line.split(':');
          if (key) {
            context.request.headers[key.toLowerCase()] = valueParts.join(':').trim();
          }
        }

        console.log(`${method} ${path}`);

        // 触发请求钩子
        await this.triggerHook('onRequest', context);

        // 如果钩子修改了数据，使用修改后的数据
        if (context.request.raw !== dataStr) {
          data = Buffer.from(context.request.raw);
          console.log('[钩子] 请求已被修改');
        }
      }

      serverTLS.write(data);
    });

    // 服务器 -> 客户端
    serverTLS.on('data', async (data) => {
      const dataStr = data.toString();

      // 解析 HTTP 响应
      if (dataStr.startsWith('HTTP/')) {
        console.log('\n========== 响应 ==========');
        const lines = dataStr.split('\r\n');
        const statusLine = lines[0];
        const [, statusCode, ...statusMessageParts] = statusLine.split(' ');

        context.response.statusCode = parseInt(statusCode);
        context.response.statusMessage = statusMessageParts.join(' ');
        context.response.raw = dataStr;

        // 解析响应头
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i];
          if (line === '') break;
          const [key, ...valueParts] = line.split(':');
          if (key) {
            context.response.headers[key.toLowerCase()] = valueParts.join(':').trim();
          }
        }

        console.log(`${statusCode} ${context.response.statusMessage}`);

        // 触发响应钩子
        await this.triggerHook('onResponse', context);

        // 如果钩子修改了数据，使用修改后的数据
        if (context.response.raw !== dataStr) {
          data = Buffer.from(context.response.raw);
          console.log('[钩子] 响应已被修改');
        }
      }

      clientTLS.write(data);
    });

    // 连接关闭处理
    clientTLS.on('end', () => {
      serverTLS.end();
      this.triggerHook('onClose', context);
    });

    serverTLS.on('end', () => {
      clientTLS.end();
      this.triggerHook('onClose', context);
    });

    clientTLS.on('error', async (err) => {
      console.error('[客户端 TLS 错误]', err.message);
      await this.triggerHook('onError', context, err);
      serverTLS.end();
    });

    serverTLS.on('error', async (err) => {
      console.error('[服务器 TLS 错误]', err.message);
      await this.triggerHook('onError', context, err);
      clientTLS.end();
    });
  }

  start() {
    this.server = net.createServer((socket) => {
      this.handleConnection(socket);
    });

    this.server.listen(this.port, () => {
      console.log('\n==========================================');
      console.log(`HTTPS 中间人代理服务器已启动`);
      console.log(`监听端口: ${this.port}`);
      console.log('==========================================');

      if (this.downstreamProxy) {
        const proxyType = this.downstreamProxy.type || 'http';
        console.log(`\n下游代理: ${proxyType.toUpperCase()} ${this.downstreamProxy.host}:${this.downstreamProxy.port}`);
        console.log(`数据流向: 客户端 -> 本代理(${this.port}) -> 下游代理 -> 目标服务器`);
      } else {
        console.log(`\n数据流向: 客户端 -> 本代理(${this.port}) -> 目标服务器（直连）`);
      }

      console.log('==========================================\n');
    });

    this.server.on('error', (err) => {
      console.error('[服务器错误]', err.message);
    });
  }

  stop() {
    if (this.server) {
      this.server.close();
      console.log('[代理] 服务器已停止');
    }
  }
}

// ============================================
// 使用示例
// ============================================

/**
 * 示例 1: 启动中间人代理 - 不使用下游代理
 */
/*
const proxy = new HTTPSMITMProxy({
  port: 8888,
  caKeyPath: './ca-key.pem',
  caCertPath: './ca-cert.pem'
});

// 注册钩子
proxy
  .on('onConnect', (context) => {
    console.log(`[钩子-连接] ${context.hostname}:${context.port}`);
  })
  .on('onRequest', (context) => {
    console.log(`[钩子-请求] ${context.request.method} ${context.request.path}`);
    
    // 修改请求头
    if (context.request.headers['user-agent']) {
      context.request.raw = context.request.raw.replace(
        /User-Agent: .+\r\n/i,
        'User-Agent: CustomAgent/1.0\r\n'
      );
    }
  })
  .on('onResponse', (context) => {
    console.log(`[钩子-响应] ${context.response.statusCode}`);
    
    // 修改响应（注入脚本）
    if (context.response.headers['content-type']?.includes('text/html')) {
      context.response.raw = context.response.raw.replace(
        '</body>',
        '<script>console.log("Injected by MITM")</script></body>'
      );
    }
  })
  .on('onError', (context, error) => {
    console.error(`[钩子-错误] ${context.hostname}: ${error.message}`);
  })
  .on('onClose', (context) => {
    console.log(`[钩子-关闭] ${context.hostname}`);
  });

proxy.start();
*/

/**
 * 示例 2: 启动中间人代理 - 使用 HTTP 下游代理
 */
/*
const proxyWithHttp = new HTTPSMITMProxy({
  port: 8888,
  caKeyPath: './ca-key.pem',
  caCertPath: './ca-cert.pem',
  downstreamProxy: {
    type: 'http',  // 或者不指定，默认为 http
    host: 'proxy.example.com',
    port: 8080,
    auth: 'username:password'  // 可选
  }
});

proxyWithHttp.start();
*/

/**
 * 示例 3: 启动中间人代理 - 使用 SOCKS5 下游代理
 */
/*
const proxyWithSocks5 = new HTTPSMITMProxy({
  port: 8888,
  caKeyPath: './ca-key.pem',
  caCertPath: './ca-cert.pem',
  downstreamProxy: {
    type: 'socks5',
    host: '127.0.0.1',
    port: 1080,
    auth: 'username:password'  // 可选
  }
});

// 添加日志钩子
proxyWithSocks5.on('onRequest', (context) => {
  const protocol = context.getMetadata('protocol');
  console.log(`[${protocol}] ${context.request.method} ${context.request.path}`);
});

proxyWithSocks5.start();
*/

/**
 * 示例 4: HTTPSProxyRequest - 不使用代理
 */
/*
async function testDirectRequest() {
  const client = new HTTPSProxyRequest('https://www.example.com/');
  
  try {
    // 使用 HTTP/2
    const result = await client.request('GET', '/', {}, true);
    console.log('协议:', client.protocol);
    console.log('状态码:', result.statusCode);
    console.log('响应体长度:', result.body.length);
  } catch (error) {
    console.error('请求失败:', error);
  }
}

testDirectRequest();
*/

/**
 * 示例 5: HTTPSProxyRequest - 使用 HTTP 代理
 */
/*
async function testWithHttpProxy() {
  const client = new HTTPSProxyRequest(
    'https://api.github.com/users/github',
    {
      type: 'http',
      host: 'proxy.example.com',
      port: 8080,
      auth: 'user:pass'
    }
  );
  
  try {
    const result = await client.request('GET', '/');
    console.log('状态码:', result.statusCode);
    console.log('响应:', result.body);
  } catch (error) {
    console.error('请求失败:', error);
  }
}

testWithHttpProxy();
*/

/**
 * 示例 6: HTTPSProxyRequest - 使用 SOCKS5 代理
 */
/*
async function testWithSocks5() {
  const client = new HTTPSProxyRequest(
    'https://www.google.com/',
    {
      type: 'socks5',
      host: '127.0.0.1',
      port: 1080,
      auth: 'user:pass'  // 可选
    }
  );
  
  try {
    // 优先使用 HTTP/2
    const result = await client.request('GET', '/', {
      'accept': 'text/html',
      'accept-language': 'en-US'
    }, true);
    
    console.log('协议:', client.protocol);
    console.log('状态码:', result.statusCode);
    console.log('响应头:', result.headers);
  } catch (error) {
    console.error('请求失败:', error);
  }
}

testWithSocks5();
*/

/**
 * 示例 7: 完整的 MITM 代理示例 - 记录所有流量
 */
/*
const fs = require('fs');

const logger = new HTTPSMITMProxy({
  port: 8888,
  caKeyPath: './ca-key.pem',
  caCertPath: './ca-cert.pem',
  downstreamProxy: {
    type: 'socks5',
    host: '127.0.0.1',
    port: 1080
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
*/

/**
 * 示例 8: 强制使用 HTTP/1.1（禁用 HTTP/2）
 */
/*
async function testHttp1Only() {
  const client = new HTTPSProxyRequest('https://www.cloudflare.com/');
  
  try {
    // 第四个参数设为 false 禁用 HTTP/2
    const result = await client.request('GET', '/', {}, false);
    console.log('协议:', client.protocol); // 应该是 http/1.1
    console.log('状态码:', result.statusCode);
  } catch (error) {
    console.error('请求失败:', error);
  }
}

testHttp1Only();
*/

export {
  HTTPSProxyRequest,
  HTTPSMITMProxy,
  ProxyContext,
  Socks5Client,
  HTTP2Client
};