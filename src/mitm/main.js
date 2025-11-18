import net from 'net';
import tls from 'tls';
import url from 'url';
import fs from 'fs';
import crypto from 'crypto';
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)

/**
 * 发送 HTTPS 请求（支持可选代理）
 * 包括：TCP 连接 -> CONNECT 隧道（可选）-> TLS 握手 -> HTTP 请求
 */
class HTTPSProxyRequest {
  constructor(targetUrl, proxyConfig = null) {
    this.targetUrl = url.parse(targetUrl);
    this.proxy = proxyConfig; // { host, port, auth } 或 null
    this.useProxy = !!proxyConfig; // 是否使用代理
    this.socket = null;
    this.tlsSocket = null;
  }

  /**
   * 步骤 1: 建立 TCP 连接（到代理或直接到目标服务器）
   */
  connectToProxy() {
    return new Promise((resolve, reject) => {
      if (this.useProxy) {
        console.log(`[TCP] 连接到代理服务器 ${this.proxy.host}:${this.proxy.port}`);

        this.socket = net.connect({
          host: this.proxy.host,
          port: this.proxy.port,
          timeout: 10000
        });
      } else {
        const targetHost = this.targetUrl.hostname;
        const targetPort = this.targetUrl.port || 443;
        console.log(`[TCP] 直接连接到目标服务器 ${targetHost}:${targetPort}`);

        this.socket = net.connect({
          host: targetHost,
          port: targetPort,
          timeout: 10000
        });
      }

      this.socket.on('connect', () => {
        console.log('[TCP] TCP 连接建立成功');
        resolve();
      });

      this.socket.on('error', (err) => {
        console.error('[TCP] 连接错误:', err.message);
        reject(err);
      });

      this.socket.on('timeout', () => {
        console.error('[TCP] 连接超时');
        this.socket.destroy();
        reject(new Error('Connection timeout'));
      });
    });
  }

  /**
   * 步骤 2: 通过 CONNECT 方法建立隧道（仅在使用代理时）
   */
  establishTunnel() {
    return new Promise((resolve, reject) => {
      // 如果不使用代理，直接跳过
      if (!this.useProxy) {
        console.log('[CONNECT] 不使用代理，跳过隧道建立');
        resolve();
        return;
      }

      const target = `${this.targetUrl.hostname}:${this.targetUrl.port || 443}`;
      console.log(`[CONNECT] 建立隧道到目标服务器 ${target}`);

      // 构造 CONNECT 请求
      let connectRequest = `CONNECT ${target} HTTP/1.1\r\n`;
      connectRequest += `Host: ${target}\r\n`;

      // 如果代理需要认证
      if (this.proxy.auth) {
        const auth = Buffer.from(this.proxy.auth).toString('base64');
        connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
      }

      connectRequest += `Connection: keep-alive\r\n`;
      connectRequest += `\r\n`;

      let responseData = '';

      const onData = (data) => {
        responseData += data.toString();

        // 检查是否收到完整的 HTTP 响应头
        if (responseData.includes('\r\n\r\n')) {
          this.socket.removeListener('data', onData);

          const statusLine = responseData.split('\r\n')[0];
          const statusCode = parseInt(statusLine.split(' ')[1]);

          console.log('[CONNECT] 收到代理响应:', statusLine);

          if (statusCode === 200) {
            console.log('[CONNECT] 隧道建立成功');
            resolve();
          } else {
            reject(new Error(`Proxy returned status ${statusCode}: ${statusLine}`));
          }
        }
      };

      this.socket.on('data', onData);
      this.socket.write(connectRequest);
    });
  }

  /**
   * 步骤 3: 在隧道上建立 TLS 连接
   */
  performTLSHandshake() {
    return new Promise((resolve, reject) => {
      console.log('[TLS] 开始 TLS 握手');

      // 在现有的 TCP socket 上包装 TLS
      this.tlsSocket = tls.connect({
        socket: this.socket,
        servername: this.targetUrl.hostname, // 用于 SNI
        rejectUnauthorized: false, // 验证证书
      });

      this.tlsSocket.on('secureConnect', () => {
        console.log('[TLS] TLS 握手成功');
        console.log('[TLS] 协议版本:', this.tlsSocket.getProtocol());
        console.log('[TLS] 加密套件:', this.tlsSocket.getCipher().name);

        // 获取证书信息
        const cert = this.tlsSocket.getPeerCertificate();
        if (cert) {
          console.log('[TLS] 服务器证书主题:', cert.subject.CN);
          console.log('[TLS] 证书颁发者:', cert.issuer.O);
        }

        resolve();
      });

      this.tlsSocket.on('error', (err) => {
        console.error('[TLS] TLS 错误:', err.message);
        reject(err);
      });
    });
  }

  /**
   * 步骤 4: 通过 TLS 连接发送 HTTP 请求（使用 http 模块）
   */
  sendHTTPRequest(method = 'GET', path = '/', headers = {}, followRedirect = false) {
    return new Promise((resolve, reject) => {
      console.log(`[HTTP] 使用 http 模块发送 ${method} 请求到 ${path}`);

      const http = require('http');

      // 准备请求选项
      const requestOptions = {
        method: method,
        path: path || '/',
        headers: {
          'Host': this.targetUrl.hostname,
          'User-Agent': 'Node.js HTTPS Proxy Client',
          'Connection': 'close',
          ...headers  // 合并自定义请求头
        },
        // 关键：使用已建立的 TLS socket
        createConnection: () => {
          console.log('[HTTP] 复用已建立的 TLS socket');
          return this.tlsSocket;
        }
      };

      // 发送 HTTP 请求
      const req = http.request(requestOptions, (res) => {
        console.log(`[HTTP] 收到响应: ${res.statusCode} ${res.statusMessage}`);
        console.log('[HTTP] 响应头:', JSON.stringify(res.headers, null, 2));

        let responseData = '';

        // 接收响应数据
        res.on('data', (chunk) => {
          responseData += chunk.toString();
        });

        res.on('end', () => {
          console.log('[HTTP] 响应接收完成，数据长度:', responseData.length);

          // 检查是否是重定向状态码
          if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
            console.log(`[HTTP] 收到重定向响应: ${res.statusCode}`);

            if (!followRedirect) {
              console.log('[HTTP] 不跟随重定向，直接返回响应');
              resolve({
                statusCode: res.statusCode,
                statusMessage: res.statusMessage,
                headers: res.headers,
                isRedirect: true,
                location: res.headers.location || null,
                body: responseData
              });
              return;
            }
          }

          // 返回完整响应
          resolve({
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            isRedirect: false,
            body: responseData
          });
        });
      });

      req.on('error', (err) => {
        console.error('[HTTP] 请求错误:', err.message);
        reject(err);
      });

      // 如果是 POST/PUT 等方法，可以在这里写入请求体
      // req.write(bodyData);

      req.end();
    });
  }

  /**
   * 步骤 4 备选: 原始方式发送 HTTP 请求（手动构造）
   */
  sendHTTPRequestRaw(method = 'GET', path = '/', headers = {}, followRedirect = false) {
    return new Promise((resolve, reject) => {
      console.log(`[HTTP] 手动构造 ${method} 请求到 ${path}`);

      // 构造 HTTP 请求
      let request = `${method} ${path || '/'} HTTP/1.1\r\n`;
      request += `Host: ${this.targetUrl.hostname}\r\n`;
      request += `Connection: close\r\n`;
      request += `User-Agent: Node.js HTTPS Proxy Client\r\n`;

      // 添加自定义请求头
      for (const [key, value] of Object.entries(headers)) {
        request += `${key}: ${value}\r\n`;
      }

      request += `\r\n`;

      let responseData = '';

      this.tlsSocket.on('data', (data) => {
        responseData += data.toString();
      });

      this.tlsSocket.on('end', () => {
        console.log('[HTTP] 响应接收完成');

        // 解析响应状态码
        const statusLine = responseData.split('\r\n')[0];
        const statusCode = parseInt(statusLine.split(' ')[1]);

        // 检查是否是重定向状态码
        if ([301, 302, 303, 307, 308].includes(statusCode)) {
          console.log(`[HTTP] 收到重定向响应: ${statusCode}`);

          if (!followRedirect) {
            console.log('[HTTP] 不跟随重定向，直接返回响应');
            resolve({
              statusCode,
              isRedirect: true,
              response: responseData,
              location: this.extractLocation(responseData)
            });
            return;
          }

          // 如果需要跟随重定向（当前默认不跟随）
          console.log('[HTTP] 跟随重定向功能已禁用');
        }

        resolve({
          statusCode,
          isRedirect: false,
          response: responseData
        });
      });

      this.tlsSocket.on('error', (err) => {
        reject(err);
      });

      this.tlsSocket.write(request);
    });
  }

  /**
   * 从响应头中提取 Location
   */
  extractLocation(response) {
    const lines = response.split('\r\n');
    for (const line of lines) {
      if (line.toLowerCase().startsWith('location:')) {
        return line.substring(9).trim();
      }
    }
    return null;
  }

  /**
   * 关闭所有连接
   */
  close() {
    if (this.tlsSocket) {
      this.tlsSocket.end();
    }
    if (this.socket) {
      this.socket.end();
    }
    console.log('[连接] 所有连接已关闭');
  }

  /**
   * 完整的请求流程
   * @param {string} method - HTTP 方法
   * @param {string} path - 请求路径
   * @param {object} headers - 请求头
   * @param {boolean} followRedirect - 是否跟随重定向（默认 false）
   */
  async request(method = 'GET', path = '/', headers = {}, followRedirect = false) {
    try {
      // 1. 建立 TCP 连接（到代理或直接到目标）
      await this.connectToProxy();

      // 2. 建立 CONNECT 隧道（仅在使用代理时）
      await this.establishTunnel();

      // 3. TLS 握手
      await this.performTLSHandshake();

      // 4. 发送 HTTP 请求
      const result = await this.sendHTTPRequest(method, path, headers, followRedirect);

      return result;
    } catch (error) {
      console.error('[错误]', error.message);
      throw error;
    } finally {
      this.close();
    }
  }
}

/**
 * ============================================
 * HTTPS 中间人代理服务器 (MITM Proxy)
 * ============================================
 * 功能：拦截、解密、查看和修改 HTTPS 流量
 * 支持：下游代理链（本代理 -> 下游代理 -> 目标服务器）
 */
class HTTPSMITMProxy {
  constructor(config) {
    this.port = config.port || 8888;
    this.caKeyPath = config.caKeyPath;   // CA 私钥路径
    this.caCertPath = config.caCertPath; // CA 证书路径
    this.caKey = null;
    this.caCert = null;
    this.certCache = new Map(); // 缓存生成的证书
    this.server = null;

    // 下游代理配置（可选）
    this.downstreamProxy = config.downstreamProxy || null;
    // downstreamProxy 格式: { host: 'proxy.example.com', port: 8080, auth: 'user:pass' }

    // 加载 CA 证书和密钥
    this.loadCA();
  }

  /**
   * 加载 CA 证书和私钥
   */
  loadCA() {
    try {
      this.caKey = fs.readFileSync(this.caKeyPath, 'utf8');
      this.caCert = fs.readFileSync(this.caCertPath, 'utf8');
      console.log('[CA] CA 证书和私钥加载成功');
    } catch (error) {
      throw new Error(`加载 CA 证书失败: ${error.message}`);
    }
  }

  /**
   * 为目标域名动态生成证书
   */
  generateCertificate(hostname) {
    // 检查缓存
    if (this.certCache.has(hostname)) {
      return this.certCache.get(hostname);
    }

    console.log(`[证书生成] 为 ${hostname} 生成证书`);

    // 生成密钥对
    const keys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    // 创建证书签名请求（简化版，实际应使用 node-forge 或 openssl）
    // 这里使用自签名证书作为示例
    const cert = this.createCertificate(hostname, keys.publicKey, keys.privateKey);

    const certPair = {
      key: keys.privateKey,
      cert: cert
    };

    // 缓存证书
    this.certCache.set(hostname, certPair);
    return certPair;
  }

  /**
   * 创建证书（使用 CA 签名）
   * 注意：这是简化实现，生产环境建议使用 node-forge 库
   */
  createCertificate(hostname, publicKey, privateKey) {
    // 简化实现：直接使用自签名
    // 实际应该用 CA 私钥签名，这里需要 node-forge 等库
    const pki = require('node-forge').pki;

    const cert = pki.createCertificate();
    cert.publicKey = pki.publicKeyFromPem(publicKey);
    cert.serialNumber = '01' + Date.now().toString(16);

    const now = new Date();
    cert.validity.notBefore = now;
    cert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

    const attrs = [{
      name: 'commonName',
      value: hostname
    }, {
      name: 'countryName',
      value: 'CN'
    }, {
      shortName: 'ST',
      value: 'Beijing'
    }, {
      name: 'localityName',
      value: 'Beijing'
    }, {
      name: 'organizationName',
      value: 'MITM Proxy'
    }];

    cert.setSubject(attrs);

    // 使用 CA 证书作为颁发者
    const caCert = pki.certificateFromPem(this.caCert);
    cert.setIssuer(caCert.subject.attributes);

    // 添加扩展
    cert.setExtensions([{
      name: 'subjectAltName',
      altNames: [{
        type: 2, // DNS
        value: hostname
      }]
    }]);

    // 用 CA 私钥签名
    const caKey = pki.privateKeyFromPem(this.caKey);
    cert.sign(caKey, require('node-forge').md.sha256.create());

    return pki.certificateToPem(cert);
  }

  /**
   * 处理客户端连接
   */
  handleConnection(clientSocket) {
    console.log('\n[新连接] 客户端已连接');

    let requestData = '';

    clientSocket.once('data', (data) => {
      requestData = data.toString();
      const lines = requestData.split('\r\n');
      const requestLine = lines[0].split(' ');
      const method = requestLine[0];
      const targetUrl = requestLine[1];

      if (method === 'CONNECT') {
        // HTTPS 请求，建立隧道
        this.handleHTTPSRequest(clientSocket, targetUrl, requestData);
      } else {
        // HTTP 请求，直接转发
        this.handleHTTPRequest(clientSocket, requestData);
      }
    });

    clientSocket.on('error', (err) => {
      console.error('[客户端错误]', err.message);
    });
  }

  /**
   * 处理 HTTPS 请求（中间人拦截）
   * 支持下游代理链
   */
  async handleHTTPSRequest(clientSocket, target, requestData) {
    const [hostname, port] = target.split(':');
    console.log(`\n[HTTPS] 拦截请求: ${hostname}:${port || 443}`);

    if (this.downstreamProxy) {
      console.log(`[下游代理] 使用下游代理: ${this.downstreamProxy.host}:${this.downstreamProxy.port}`);
    } else {
      console.log('[直连] 直接连接到目标服务器');
    }

    try {
      // 1. 向客户端返回 200 Connection Established
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

      // 2. 生成伪造证书
      const certPair = this.generateCertificate(hostname);

      // 3. 将客户端 socket 升级为 TLS（作为服务器）
      const clientTLSSocket = new tls.TLSSocket(clientSocket, {
        isServer: true,
        key: certPair.key,
        cert: certPair.cert,
        SNICallback: (servername, cb) => {
          const cert = this.generateCertificate(servername);
          cb(null, tls.createSecureContext({
            key: cert.key,
            cert: cert.cert
          }));
        }
      });

      // 4. 连接到目标服务器（直连或通过下游代理）
      if (this.downstreamProxy) {
        // 通过下游代理连接
        await this.connectViaDownstreamProxy(clientTLSSocket, hostname, port || 443);
      } else {
        // 直接连接到目标服务器
        await this.connectDirectly(clientTLSSocket, hostname, port || 443);
      }

    } catch (error) {
      console.error('[HTTPS 处理错误]', error.message);
      clientSocket.end();
    }
  }

  /**
   * 直接连接到目标服务器（不使用下游代理）
   */
  async connectDirectly(clientTLSSocket, hostname, port) {
    return new Promise((resolve, reject) => {
      console.log(`[直连] 连接到真实服务器 ${hostname}:${port}`);

      const serverSocket = net.connect({
        host: hostname,
        port: port
      });

      serverSocket.on('connect', () => {
        console.log(`[直连] 已连接到真实服务器 ${hostname}`);

        const serverTLSSocket = tls.connect({
          socket: serverSocket,
          servername: hostname,
          rejectUnauthorized: false
        });

        serverTLSSocket.on('secureConnect', () => {
          console.log('[TLS] 与真实服务器的 TLS 握手完成');

          // 双向转发数据，并拦截查看
          this.interceptAndForward(clientTLSSocket, serverTLSSocket, hostname);
          resolve();
        });

        serverTLSSocket.on('error', (err) => {
          console.error('[服务器 TLS 错误]', err.message);
          clientTLSSocket.end();
          reject(err);
        });
      });

      serverSocket.on('error', (err) => {
        console.error('[服务器连接错误]', err.message);
        clientTLSSocket.end();
        reject(err);
      });
    });
  }

  /**
   * 通过下游代理连接到目标服务器
   */
  async connectViaDownstreamProxy(clientTLSSocket, hostname, port) {
    return new Promise((resolve, reject) => {
      console.log(`[下游代理] 连接到下游代理 ${this.downstreamProxy.host}:${this.downstreamProxy.port}`);

      // 1. 连接到下游代理服务器
      const proxySocket = net.connect({
        host: this.downstreamProxy.host,
        port: this.downstreamProxy.port,
        timeout: 10000
      });

      proxySocket.on('connect', () => {
        console.log('[下游代理] TCP 连接到下游代理成功');

        // 2. 向下游代理发送 CONNECT 请求
        const target = `${hostname}:${port}`;
        let connectRequest = `CONNECT ${target} HTTP/1.1\r\n`;
        connectRequest += `Host: ${target}\r\n`;

        // 如果下游代理需要认证
        if (this.downstreamProxy.auth) {
          const auth = Buffer.from(this.downstreamProxy.auth).toString('base64');
          connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }

        connectRequest += `Connection: keep-alive\r\n`;
        connectRequest += `\r\n`;

        let responseData = '';

        const onData = (data) => {
          responseData += data.toString();

          // 检查是否收到完整的 HTTP 响应头
          if (responseData.includes('\r\n\r\n')) {
            proxySocket.removeListener('data', onData);

            const statusLine = responseData.split('\r\n')[0];
            const statusCode = parseInt(statusLine.split(' ')[1]);

            console.log('[下游代理] 收到 CONNECT 响应:', statusLine);

            if (statusCode === 200) {
              console.log('[下游代理] 隧道建立成功');

              // 3. 在下游代理隧道上建立 TLS 连接到目标服务器
              const serverTLSSocket = tls.connect({
                socket: proxySocket,
                servername: hostname,
                rejectUnauthorized: false
              });

              serverTLSSocket.on('secureConnect', () => {
                console.log('[TLS] 通过下游代理与真实服务器的 TLS 握手完成');

                // 4. 双向转发数据，并拦截查看
                this.interceptAndForward(clientTLSSocket, serverTLSSocket, hostname);
                resolve();
              });

              serverTLSSocket.on('error', (err) => {
                console.error('[服务器 TLS 错误]', err.message);
                clientTLSSocket.end();
                reject(err);
              });
            } else {
              const error = new Error(`下游代理返回错误状态 ${statusCode}`);
              console.error('[下游代理错误]', error.message);
              clientTLSSocket.end();
              reject(error);
            }
          }
        };

        proxySocket.on('data', onData);
        proxySocket.write(connectRequest);
      });

      proxySocket.on('error', (err) => {
        console.error('[下游代理连接错误]', err.message);
        clientTLSSocket.end();
        reject(err);
      });

      proxySocket.on('timeout', () => {
        console.error('[下游代理] 连接超时');
        proxySocket.destroy();
        clientTLSSocket.end();
        reject(new Error('Downstream proxy connection timeout'));
      });
    });
  }

  /**
   * 拦截并转发数据
   */
  interceptAndForward(clientTLSSocket, serverTLSSocket, hostname) {
    console.log(`[拦截] 开始拦截 ${hostname} 的流量`);

    // 客户端 -> 服务器( clientTlsSocket -> ProxyCast -> serverTlsSocket)
    clientTLSSocket.on('data', (data) => {
      const dataStr = data.toString();

      // 解析 HTTP 请求
      if (dataStr.startsWith('GET') || dataStr.startsWith('POST') ||
        dataStr.startsWith('PUT') || dataStr.startsWith('DELETE')) {
        console.log('\n========== 拦截到客户端请求 ==========');
        const lines = dataStr.split('\r\n');
        console.log('请求行:', lines[0]);
        console.log('Host:', hostname);

        // 可以在这里修改请求
        // 例如：添加自定义请求头
        // data = Buffer.from(dataStr.replace('\r\n\r\n', '\r\nX-Custom-Header: Modified\r\n\r\n'));
      }

      serverTLSSocket.write(data);
    });

    // 服务器 -> 客户端 (serverTlsSocket -> ProxyCast -> clientTlsSocket)
    serverTLSSocket.on('data', (data) => {
      const dataStr = data.toString();
      console.log('服务器 -> 客户端:\r\n\r\n', dataStr)

      // 解析 HTTP 响应
      if (dataStr.startsWith('HTTP/')) {
        console.log('\n========== 拦截到服务器响应 ==========');
        const lines = dataStr.split('\r\n');
        console.log('状态行:', lines[0]);

        // 查找 Content-Type
        const contentType = lines.find(line => line.toLowerCase().startsWith('content-type:'));
        if (contentType) {
          console.log(contentType);
        }

        // 可以在这里修改响应
        // 例如：修改响应内容
        // if (dataStr.includes('</body>')) {
        //   data = Buffer.from(dataStr.replace('</body>', '<script>console.log("Injected by MITM")</script></body>'));
        // }
      }

      clientTLSSocket.write(data);
    });

    clientTLSSocket.on('end', () => {
      serverTLSSocket.end();
    });

    serverTLSSocket.on('end', () => {
      clientTLSSocket.end();
    });

    clientTLSSocket.on('error', (err) => {
      console.error('[客户端 TLS 错误]', err.message);
      serverTLSSocket.end();
    });

    serverTLSSocket.on('error', (err) => {
      console.error('[服务器 TLS 错误]', err.message);
      clientTLSSocket.end();
    });
  }

  /**
   * 处理 HTTP 请求（明文，直接转发）
   */
  handleHTTPRequest(clientSocket, requestData) {
    console.log('[HTTP] 明文 HTTP 请求');
    // 这里可以实现 HTTP 代理转发逻辑
    clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\nHTTP not supported, use HTTPS');
  }

  /**
   * 启动代理服务器
   */
  start() {
    this.server = net.createServer((socket) => {
      this.handleConnection(socket);
    });

    this.server.listen(this.port, () => {
      console.log('\n==========================================');
      console.log(`HTTPS 中间人代理服务器已启动`);
      console.log(`监听端口: ${this.port}`);
      console.log('==========================================\n');
      console.log('配置浏览器代理:');
      console.log(`  HTTP 代理: 127.0.0.1:${this.port}`);
      console.log(`  HTTPS 代理: 127.0.0.1:${this.port}`);
      console.log('\n请确保已将 CA 证书安装到系统信任根证书');

      if (this.downstreamProxy) {
        console.log('\n==========================================');
        console.log('下游代理配置:');
        console.log(`  代理服务器: ${this.downstreamProxy.host}:${this.downstreamProxy.port}`);
        console.log(`  认证: ${this.downstreamProxy.auth ? '已启用' : '未启用'}`);
        console.log('\n数据流向:');
        console.log(`  客户端 -> 本代理(${this.port}) -> 下游代理(${this.downstreamProxy.host}:${this.downstreamProxy.port}) -> 目标服务器`);
      } else {
        console.log('\n数据流向:');
        console.log(`  客户端 -> 本代理(${this.port}) -> 目标服务器（直连）`);
      }

      console.log('==========================================\n');
    });

    this.server.on('error', (err) => {
      console.error('服务器错误:', err.message);
    });
  }

  /**
   * 停止代理服务器
   */
  stop() {
    if (this.server) {
      this.server.close();
      console.log('[代理] 服务器已停止');
    }
  }
}

// ============ 使用示例 ============

// 示例 1: 启动中间人代理服务器（不使用下游代理）
/*
const mitmProxy = new HTTPSMITMProxy({
  port: 8888,
  caKeyPath: './ca-key.pem',    // CA 私钥路径
  caCertPath: './ca-cert.pem'   // CA 证书路径
});

mitmProxy.start();
*/

// 示例 1.5: 启动中间人代理服务器（使用下游代理）
/*
const mitmProxyWithDownstream = new HTTPSMITMProxy({
  port: 8888,
  caKeyPath: './ca-key.pem',
  caCertPath: './ca-cert.pem',
  // 配置下游代理
  downstreamProxy: {
    host: 'downstream-proxy.example.com',
    port: 8080,
    auth: 'username:password'  // 可选：如果下游代理需要认证
  }
});

mitmProxyWithDownstream.start();

// 数据流向:
// 浏览器 -> 本地MITM代理(8888) -> 下游代理(8080) -> 目标服务器
// 你可以在MITM代理中拦截并查看所有解密后的HTTPS流量
*/

// 示例 2: 不使用代理直接发送 HTTPS 请求
/*
async function testDirectRequest() {
  // 不传入代理配置，直接连接目标服务器
  const client = new HTTPSProxyRequest('https://www.example.com/');
  
  try {
    const result = await client.request('GET', '/', {
      'Accept': 'text/html',
      'Accept-Language': 'zh-CN,zh;q=0.9'
    });
    
    console.log('状态码:', result.statusCode);
    console.log('响应体:', result.body.substring(0, 500));
  } catch (error) {
    console.error('请求失败:', error);
  }
}
*/

// 示例 3: 通过代理发送 HTTPS 请求
/*
async function testProxyRequest() {
  // 传入代理配置
  const client = new HTTPSProxyRequest(
    'https://www.example.com/',
    {
      host: 'proxy.example.com',
      port: 8080,
      auth: 'username:password' // 可选
    }
  );
  
  try {
    const result = await client.request('GET', '/', {
      'Accept': 'application/json',
      'Accept-Language': 'zh-CN'
    });
    
    console.log('状态码:', result.statusCode);
    console.log('状态消息:', result.statusMessage);
    console.log('Content-Type:', result.headers['content-type']);
    console.log('响应体:', result.body.substring(0, 200));
  } catch (error) {
    console.error('请求失败:', error);
  }
}
*/

// 示例 4: 处理重定向（不跟随）
/*
async function testRedirect() {
  // 可以使用代理也可以不使用
  const client = new HTTPSProxyRequest('https://github.com/');
  
  const result = await client.request('GET', '/');
  
  if (result.isRedirect) {
    console.log(`检测到重定向 ${result.statusCode} -> ${result.location}`);
    console.log('响应头:', result.headers);
    console.log('响应体:', result.body);
  } else {
    console.log('状态码:', result.statusCode);
    console.log('响应头:', result.headers);
    console.log('响应体长度:', result.body.length);
  }
}
*/

// 示例 5: 根据环境变量决定是否使用代理
/*
async function testWithEnvProxy() {
  const proxyConfig = process.env.HTTP_PROXY ? {
    host: new URL(process.env.HTTP_PROXY).hostname,
    port: new URL(process.env.HTTP_PROXY).port
  } : null;
  
  const client = new HTTPSProxyRequest(
    'https://api.example.com/data',
    proxyConfig  // 如果环境变量未设置，则为 null，不使用代理
  );
  
  const result = await client.request('GET', '/');
  console.log('响应状态:', result.statusCode);
}
*/

export {
  HTTPSProxyRequest,
  HTTPSMITMProxy
};