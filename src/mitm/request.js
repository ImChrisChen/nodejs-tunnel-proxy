import { HTTPSProxyRequest } from './main.js'

async function testProxyRequest() {
  const client = new HTTPSProxyRequest(
    'https://google.com',
    // 'https://baidu.com',
    {
      host: '127.0.0.1',
      port: 8888,
      // auth: 'username:password' // 可选
    }
  );

  try {
    const response = await client.request('GET', '/');
    // console.log('响应:', response.substring(0, 500));
    console.log('响应:', response);
  } catch (error) {
    console.error('请求失败:', error);
  }
}

testProxyRequest()