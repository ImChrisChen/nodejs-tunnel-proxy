import { HTTPSMITMProxy } from "./main.js";
const mitmProxy = new HTTPSMITMProxy({
  port: 8888,
  caKeyPath: '/Users/chris/.proxycast/certs/root-ca.key',    // CA 私钥路径
  caCertPath: '/Users/chris/.proxycast/certs/root-ca.crt',   // CA 证书路径
  downstreamProxy: {
    host: '127.0.0.1',
    port: 7890 // 指向另一个代理
  }
});

mitmProxy.start();