/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run "npm run dev" in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run "npm run deploy" to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */
// @ts-ignore
import { connect } from 'cloudflare:sockets';

const proxyIPs = ['cdn-b100.xn--b6gac.eu.org'];
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    switch (url.pathname) {
      case '/dns-query':
        url.hostname = "8.8.8.8"
        // return new Response(url.toString(), {
        //     status: 200
        // });
        return await fetch(url.toString());
      case '/connect': // for test connect to cf socket
        return await bepassOverWs(request)
      default:
        return new Response(JSON.stringify(request.cf, null, 4), {
            status: 200,
            headers: {
                "Content-Type": "application/json;charset=utf-8",
            },
        });
    }
  },
};

async function bepassOverWs(request) {
  const params = {}
  const url = new URL(request.url)
  const queryString = url.search.slice(1).split('&')

  queryString.forEach(item => {
      const kv = item.split('=')
      if (kv[0]) params[kv[0]] = kv[1] || true
  })

  const destinationHost = params["host"]
  const destinationPort = params["port"]

  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let address = '';
  let portWithRandomLog = '';
  const log = (info, event) => {
      console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
  };

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, log);

  let remoteSocketWapper = {
      value: null,
  };

  // ws --> remote
  readableWebSocketStream.pipeTo(new WritableStream({
      async write(chunk, controller) {
        if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter()
            await writer.write(chunk);
            writer.releaseLock();
            return;
        }
        handleTCPOutBound(remoteSocketWapper, destinationHost, destinationPort, chunk, webSocket, log);
      },
      close() {
          log(`readableWebSocketStream is close`);
      },
      abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
      },
  })).catch((err) => {
      log('readableWebSocketStream pipeTo error', err);
  });

  return new Response(null, {
      status: 101,
      // @ts-ignore
      webSocket: client,
  });
}

function makeReadableWebSocketStream(webSocketServer, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
      start(controller) {
          webSocketServer.addEventListener('message', (event) => {
              if (readableStreamCancel) {
                  return;
              }
              const message = event.data;
              controller.enqueue(message);
          });

          // The event means that the client closed the client -> server stream.
          // However, the server -> client stream is still open until you call close() on the server side.
          // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
          webSocketServer.addEventListener('close', () => {
              // client send close, need close server
              // if stream is cancel, skip controller.close
              safeCloseWebSocket(webSocketServer);
              if (readableStreamCancel) {
                  return;
              }
              controller.close();
          }
          );
          webSocketServer.addEventListener('error', (err) => {
              log('webSocketServer has error');
              controller.error(err);
            }
          );
      },
      cancel(reason) {
          // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
          // 2. if readableStream is cancel, all controller.close/enqueue need skip,
          // 3. but from testing controller.error still work even if readableStream is cancel
          if (readableStreamCancel) {
              return;
          }
          log(`ReadableStream was canceled, due to ${reason}`)
          readableStreamCancel = true;
          safeCloseWebSocket(webSocketServer);
      }
  });

  return stream;
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log,) {
  async function connectAndWrite(address, port) {
      const tcpSocket = connect({
          hostname: address,
          port: port,
      });
      remoteSocket.value = tcpSocket;
      return tcpSocket;
  }

  // if the cf connect tcp socket have no incoming data, we retry to redirect ip
  async function retry() {
      const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote)
      // no matter retry success or not, close websocket
      tcpSocket.closed.catch(error => {
          console.log('retry tcpSocket closed error', error);
      }).finally(() => {
          safeCloseWebSocket(webSocket);
      })
      remoteSocketToWS(tcpSocket, webSocket, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  // when remoteSocket is ready, pass to websocket
  // remote--> ws
  remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
  // remote--> ws
  let remoteChunkCount = 0;
  let chunks = [];
  let hasIncomingData = false; // check if remoteSocket has incoming data
  await remoteSocket.readable
      .pipeTo(
          new WritableStream({
              start() {
              },
              async write(chunk, controller) {
                  hasIncomingData = true;
                  // remoteChunkCount++;
                  if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                      controller.error(
                          'webSocket.readyState is not open, maybe close'
                      );
                  }
                  // seems no need rate limit this, CF seems fix this??..
                  // if (remoteChunkCount > 20000) {
                  // 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
                  // 	await delay(1);
                  // }
                  webSocket.send(chunk);
              },
              close() {
                  log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                  // safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
              },
              abort(reason) {
                  console.error(`remoteConnection!.readable abort`, reason);
              },
          })
      )
      .catch((error) => {
          console.error(
              `remoteSocketToWS has exception `,
              error.stack || error
          );
          safeCloseWebSocket(webSocket);
      });

  // seems is cf connect socket have error,
  // 1. Socket.closed will have error
  // 2. Socket.readable will be close without any data coming
  if (hasIncomingData === false && retry) {
      log(`retry`)
      retry();
  }
}

function safeCloseWebSocket(socket) {
  try {
      if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
          socket.close();
      }
  } catch (error) {
      console.error('safeCloseWebSocket error', error);
  }
}
