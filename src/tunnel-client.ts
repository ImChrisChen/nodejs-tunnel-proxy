import net from 'net';

// 端口定义
const SERVER_HOST = '127.0.0.1'; // 服务端 IP (测试环境用 localhost)
const TUNNEL_PORT = 9000;
const LOCAL_SERVICE_PORT = 3000; // 内网 Web 服务端口

let tunnel: net.Socket | null = null;

function connectTunnel() {
  tunnel = net.connect({ host: SERVER_HOST, port: TUNNEL_PORT }, () => {
    console.log('【客户端】成功连接到服务端，隧道已打通。');
  });

  // 接收来自服务端的数据 (也就是公网用户的请求)
  tunnel.on('data', (data) => {
    console.log('【客户端】收到公网请求数据，转发到内网服务...');

    // --- 步骤 4: 将公网请求转发到内网服务 ---
    const localService = net.connect({ host: '127.0.0.1', port: LOCAL_SERVICE_PORT }, () => {
      localService.write(data); // 将公网请求数据写入内网服务
    });

    // 接收内网服务的响应，并写回给隧道 (发送回公网服务端)
    localService.on('data', (responseData) => {
      tunnel?.write(responseData); // 通过隧道将响应发回服务端
    });

    localService.on('error', (err) => {
      console.error('【内网服务错误】', err.message);
      // 实际应用中需要向服务端发送错误响应
    });
  });

  // 自动重连机制
  tunnel.on('end', () => {
    console.log('【客户端】隧道断开，尝试重连...');
    setTimeout(connectTunnel, 3000);
  });

  tunnel.on('error', (err) => {
    console.error('【客户端错误】', err.message);
    tunnel?.destroy(); // 销毁连接，触发 'end' 事件进行重连
  });
}

connectTunnel();