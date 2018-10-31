'use strict';

var _socketclusterServer = require('socketcluster-server');

var _socketclusterServer2 = _interopRequireDefault(_socketclusterServer);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var OPTIONS = {
  hostname: 'localhost',
  port: 9009
};

var server = void 0;
// const nrPeers = 3

// Start WebSocket server

server = _socketclusterServer2.default.listen(OPTIONS.port);
server.on('closure', function () {});
server.on('disconnection', function () {});
server.once('ready', function () {
  console.log('ready');
});