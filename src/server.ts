import { sleep, sleepSync } from 'bun';
import http from 'http';

const server = http.createServer(async (req, res) => {
  console.log('url:', req.url)
  console.log('method:', req.method)
  console.log('headers:', req.headers)
  await sleep(5000)
  res.end('Hello from internal service on 3000!');
})

server.listen(3000).on('listening', () => {
  console.log('Server running at http://127.0.0.1:3000/');
})
