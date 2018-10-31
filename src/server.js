import socketClusterServer from 'socketcluster-server'
const OPTIONS = {
  hostname: 'localhost',
  port: 9009
}

let server
// const nrPeers = 3

// Start WebSocket server

server = socketClusterServer.listen(OPTIONS.port)
server.on('closure', () => {})
server.on('disconnection', () => {})
server.once('ready', () => {
  console.log('ready')
})
