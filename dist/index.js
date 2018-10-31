'use strict';

var _regenerator = require('babel-runtime/regenerator');

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = require('babel-runtime/helpers/asyncToGenerator');

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

var _classCallCheck2 = require('babel-runtime/helpers/classCallCheck');

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = require('babel-runtime/helpers/createClass');

var _createClass3 = _interopRequireDefault(_createClass2);

var _possibleConstructorReturn2 = require('babel-runtime/helpers/possibleConstructorReturn');

var _possibleConstructorReturn3 = _interopRequireDefault(_possibleConstructorReturn2);

var _inherits2 = require('babel-runtime/helpers/inherits');

var _inherits3 = _interopRequireDefault(_inherits2);

var _socketclusterClient = require('socketcluster-client');

var _socketclusterClient2 = _interopRequireDefault(_socketclusterClient);

var _masqCommon = require('masq-common');

var _masqCommon2 = _interopRequireDefault(_masqCommon);

var _events = require('events');

var _events2 = _interopRequireDefault(_events);

var _masqCrypto = require('masq-crypto');

var _masqCrypto2 = _interopRequireDefault(_masqCrypto);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// Those errors must be added into masq-common
var newErrors = {
  CHANNELNOTSUBSCRIBED: 'The channel is not subscribed',
  NOCOMMONKEY: 'The ECDH common key does not exist',
  NOECPRIVATEKEY: 'The EC private key does not exist',
  NORSAPUBLICKEYSTORED: 'The sender RSA public key does not exist',
  VERIFICATIONFAILED: 'The received EC public key verification failed, check the registered sender RSA public key',
  RSAEXCHANGEENCKEY: 'The ephemeral AES encryption key used to encrypt RSA public keys during pairing operation is not known'
};
var ERRORS = Object.assign(_masqCommon2.default.ERRORS, newErrors);

/**
 * The message format to send EC public key
 * @typedef {Object} ECPublicKeyMsgFormat
 * @property {string} from - The sender channel
 * @property {string} event - The event (ECPublicKey)
 * @property {string} to - The receiver channel
 * @property {boolean} ack - The status of message, true if response of previous msg
 * @property {Object} data - The message data
 * @property {string} data.ECPublicKey - The hex string format of EC public key
 * @property {string} data.signature - The hex string signature
 */

/**
 * The message format to send RSA public key
 * @typedef {Object} RSAPublicKeyMsgFormat
 * @property {string} from - The sender channel
 * @property {string} event - The event (ECPublicKey)
 * @property {string} to - The receiver channel
 * @property {boolean} ack - The status of message, true if response of previous msg
 * @property {Object} data - The message data
 * @property {Object} data.key - The (stringified and encrypted) RSA public key
*/

// default settings
var DEFAULTS = {
  hostname: 'localhost',
  port: 9009,
  multiplex: false,
  autoReconnectOptions: {
    randomness: 1000,
    multiplier: 1.5,
    maxDelay: 7000
  }
};

var debug = false;
var log = function log() {
  for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
    args[_key] = arguments[_key];
  }

  var reg = function reg(all, cur) {
    if (typeof cur === 'string') {
      return all + cur;
    } else {
      return all + cur.toString();
    }
  };
  if (debug) {
    console.log('[Masq sync]', args.reduce(reg, ''));
  }
};

/**
 * Client class.
 *
 * @param  {Object} options List of constructor parameters
 * @param  {Object} options.ID The id of the socket (hash of the RSA public key)
 * @param  {Object} options.masqStore The instance of masq
 */

var Client = function (_EventEmitter) {
  (0, _inherits3.default)(Client, _EventEmitter);

  function Client(options) {
    (0, _classCallCheck3.default)(this, Client);

    // override default options
    var _this = (0, _possibleConstructorReturn3.default)(this, (Client.__proto__ || Object.getPrototypeOf(Client)).call(this));

    _this.options = Object.assign({}, DEFAULTS, options);
    _this.ID = _this.options.id || _masqCommon2.default.generateUUID();
    _this.channels = {};
    _this.RSAExchangeEncKey = null;
    _this.commonECDHDerivedKey = null;
    _this.EC = null;
    _this.RSA = null;
    _this.masqStore = _this.options.masqStore;
    _this.socket = undefined;
    _this.myChannel = undefined;
    return _this;
  }

  /**
   * Init a new socketClient connection.
   *
   * @return  {Promise} Promise resolves/rejects upon connection or errors
   */


  (0, _createClass3.default)(Client, [{
    key: 'init',
    value: function init() {
      var _this2 = this;

      return new Promise(function (resolve, reject) {
        _this2.socket = _socketclusterClient2.default.create(_this2.options);

        _this2.socket.on('error', function (err) {
          return reject(err);
        });

        _this2.socket.on('close', function (err) {
          return reject(err);
        });

        _this2.socket.on('connect', (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee() {
          return _regenerator2.default.wrap(function _callee$(_context) {
            while (1) {
              switch (_context.prev = _context.next) {
                case 0:
                  _context.next = 2;
                  return _this2.subscribeSelf();

                case 2:
                  return _context.abrupt('return', resolve());

                case 3:
                case 'end':
                  return _context.stop();
              }
            }
          }, _callee, _this2);
        })));
      });
    }

    /**
     * Send a message to the channel
     * @param {string} channel - The channel name
     * @param {Object} msg -  The message
     */

  }, {
    key: 'sendMessage',
    value: function sendMessage(channel, msg) {
      // checkParameter(msg)
      if (!this.channels[channel]) {
        throw _masqCommon2.default.generateError(ERRORS.CHANNELNOTSUBSCRIBED);
      }
      this.channels[channel].socket.publish(msg);
    }

    /**
     * This function stores the RSAExchangeEncKey in the current masq-sync
     * instance to en/decrypt the exchanged of the RSA public keys during
     * pairing operation/communications.
     *
     * @param {string} RSAExchangeEncKey - The hexadecimal string of the symmetric key (128bits)
     */

  }, {
    key: 'saveRSAExchangeEncKey',
    value: function saveRSAExchangeEncKey(RSAExchangeEncKey) {
      this.RSAExchangeEncKey = _masqCrypto2.default.utils.hexStringToBuffer(RSAExchangeEncKey);
    }

    /**
     * Send the long term public key, encrypted with an ephemeral
     * symmetric key (exchanged through another channel)
     * The symmetric key is given as parameter on the device which
     * asks the pairing.
     * The paired device must generate the symmetric key and call
     * saveRSAExchangeEncKey method before sending the QRCOde or pairing link
     * @param {Object} params - The public key exchange parameters
     * @param {string} [params.from] - The sender channel
     * @param {string} [params.publicKey] - The public key object
     * @param {string} [params.symmetricKey] - The hexadecimal string of the symmetric key (128bits)
     * @param {boolean} params.ack - Indicate if this is a response to a previous event
     */

  }, {
    key: 'sendRSAPublicKey',
    value: function () {
      var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(params) {
        var cipherAES, currentDevice, encPublicKey, msg;
        return _regenerator2.default.wrap(function _callee2$(_context2) {
          while (1) {
            switch (_context2.prev = _context2.next) {
              case 0:
                if (params.symmetricKey) {
                  this.RSAExchangeEncKey = _masqCrypto2.default.utils.hexStringToBuffer(params.symmetricKey);
                }

                if (!(!params.symmetricKey && !this.RSAExchangeEncKey)) {
                  _context2.next = 3;
                  break;
                }

                throw _masqCommon2.default.generateError(ERRORS.RSAEXCHANGEENCKEY);

              case 3:
                cipherAES = new _masqCrypto2.default.AES({
                  mode: _masqCrypto2.default.aesModes.GCM,
                  key: params.symmetricKey ? _masqCrypto2.default.utils.hexStringToBuffer(params.symmetricKey) : this.RSAExchangeEncKey,
                  keySize: 128
                });
                _context2.next = 6;
                return this.masqStore.getCurrentDevice();

              case 6:
                currentDevice = _context2.sent;
                _context2.next = 9;
                return cipherAES.encrypt(JSON.stringify(currentDevice.publicKeyRaw));

              case 9:
                encPublicKey = _context2.sent;
                msg = {
                  from: this.ID,
                  event: 'publicKey',
                  data: { key: encPublicKey },
                  to: params.to,
                  ack: params.ack
                };

                this.sendMessage(msg.to, msg);

              case 12:
              case 'end':
                return _context2.stop();
            }
          }
        }, _callee2, this);
      }));

      function sendRSAPublicKey(_x) {
        return _ref2.apply(this, arguments);
      }

      return sendRSAPublicKey;
    }()

    /**
     * Send the EC public key along with associated signature
     * The EC key pair is generated and stored in this.EC
     * @param {Object} params - The EC public key exchange parameters
     * @param {string} params.to - The channel name
     * @param {boolean} ack - Indicate if this is a response to a previous event
     */

  }, {
    key: 'sendECPublicKey',
    value: function () {
      var _ref3 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(params) {
        var ECPublicKey, currentDevice, signature, msg;
        return _regenerator2.default.wrap(function _callee3$(_context3) {
          while (1) {
            switch (_context3.prev = _context3.next) {
              case 0:
                if (this.EC) {
                  _context3.next = 4;
                  break;
                }

                this.EC = new _masqCrypto2.default.EC({});
                _context3.next = 4;
                return this.EC.genECKeyPair();

              case 4:
                _context3.next = 6;
                return this.EC.exportKeyRaw();

              case 6:
                ECPublicKey = _context3.sent;
                _context3.next = 9;
                return this.masqStore.getCurrentDevice();

              case 9:
                currentDevice = _context3.sent;


                if (!this.RSA) {
                  this.RSA = new _masqCrypto2.default.RSA({});
                  this.RSA.publicKey = currentDevice.publicKey;
                  this.RSA.privateKey = currentDevice.privateKey;
                }
                _context3.next = 13;
                return this.RSA.signRSA(ECPublicKey);

              case 13:
                signature = _context3.sent;
                msg = {
                  from: this.ID,
                  event: 'ECPublicKey',
                  to: params.to,
                  ack: params.ack,
                  data: {
                    key: _masqCrypto2.default.utils.bufferToHexString(ECPublicKey),
                    signature: _masqCrypto2.default.utils.bufferToHexString(signature)
                  }
                };


                this.sendMessage(msg.to, msg);

              case 16:
              case 'end':
                return _context3.stop();
            }
          }
        }, _callee3, this);
      }));

      function sendECPublicKey(_x2) {
        return _ref3.apply(this, arguments);
      }

      return sendECPublicKey;
    }()

    /**
     * Send the group channel key, encrypted with common derived secret key (ECDH)
     * @param {Object} params - The group key exchange parameters
     * @param {string} params.to - The channel name
     * @param {string} params.groupkey - The group key (hex string of a 128 bit AES key)
     */

  }, {
    key: 'sendChannelKey',
    value: function () {
      var _ref4 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee4(params) {
        var cipherAES, encGroupKey, msg;
        return _regenerator2.default.wrap(function _callee4$(_context4) {
          while (1) {
            switch (_context4.prev = _context4.next) {
              case 0:
                if (this.commonECDHDerivedKey) {
                  _context4.next = 2;
                  break;
                }

                throw _masqCommon2.default.generateError(ERRORS.NOCOMMONKEY);

              case 2:
                cipherAES = new _masqCrypto2.default.AES({
                  mode: _masqCrypto2.default.aesModes.GCM,
                  key: this.commonECDHDerivedKey,
                  keySize: 128
                });
                _context4.next = 5;
                return cipherAES.encrypt(params.groupkey);

              case 5:
                encGroupKey = _context4.sent;
                msg = {
                  to: params.to,
                  event: 'channelKey',
                  from: this.ID,
                  data: { key: encGroupKey }
                };

                this.sendMessage(msg.to, msg);

              case 8:
              case 'end':
                return _context4.stop();
            }
          }
        }, _callee4, this);
      }));

      function sendChannelKey(_x3) {
        return _ref4.apply(this, arguments);
      }

      return sendChannelKey;
    }()
  }, {
    key: 'readyToTransfer',
    value: function readyToTransfer(channel) {
      var msg = {
        event: 'readyToTransfer',
        from: this.ID
      };
      this.sendMessage(channel, msg);
    }

    /**
     * Decryption of the received RSA public key with this.RSAExchangeEncKey.
     * this.RSAExchangeEncKey is, stored by the device which generates it, i.e. the
     * device which is asked to be paired, and, retrieved by another channel for the
     * paired device.
     * @param {Object} key - The stringified and encrypted RSA public key
     * @return {Object} - The decrypted but still stringified RSA public key
     */

  }, {
    key: 'decryptRSAPublicKey',
    value: function () {
      var _ref5 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee5(key) {
        var cipherAES, decPublicKey;
        return _regenerator2.default.wrap(function _callee5$(_context5) {
          while (1) {
            switch (_context5.prev = _context5.next) {
              case 0:
                cipherAES = new _masqCrypto2.default.AES({
                  mode: _masqCrypto2.default.aesModes.GCM,
                  key: this.RSAExchangeEncKey,
                  keySize: 128
                });
                _context5.next = 3;
                return cipherAES.decrypt(key);

              case 3:
                decPublicKey = _context5.sent;
                return _context5.abrupt('return', decPublicKey);

              case 5:
              case 'end':
                return _context5.stop();
            }
          }
        }, _callee5, this);
      }));

      function decryptRSAPublicKey(_x4) {
        return _ref5.apply(this, arguments);
      }

      return decryptRSAPublicKey;
    }()
  }, {
    key: 'decryptGroupKey',
    value: function () {
      var _ref6 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee6(msg) {
        var cipherAES, decGroupKey;
        return _regenerator2.default.wrap(function _callee6$(_context6) {
          while (1) {
            switch (_context6.prev = _context6.next) {
              case 0:
                if (this.commonECDHDerivedKey) {
                  _context6.next = 2;
                  break;
                }

                throw _masqCommon2.default.generateError(ERRORS.NOCOMMONKEY);

              case 2:
                cipherAES = new _masqCrypto2.default.AES({
                  mode: _masqCrypto2.default.aesModes.GCM,
                  key: this.commonECDHDerivedKey,
                  keySize: 128
                });
                _context6.next = 5;
                return cipherAES.decrypt(msg.data.key);

              case 5:
                decGroupKey = _context6.sent;
                return _context6.abrupt('return', decGroupKey);

              case 7:
              case 'end':
                return _context6.stop();
            }
          }
        }, _callee6, this);
      }));

      function decryptGroupKey(_x5) {
        return _ref6.apply(this, arguments);
      }

      return decryptGroupKey;
    }()

    /**
     *
     * @param {string} from - The sender of the RSA public key
     * @param {Object} key - The stringified RSA public key
     */

  }, {
    key: 'storeRSAPublicKey',
    value: function () {
      var _ref7 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee7(from, key) {
        var device;
        return _regenerator2.default.wrap(function _callee7$(_context7) {
          while (1) {
            switch (_context7.prev = _context7.next) {
              case 0:
                device = {
                  name: from,
                  RSAPublicKey: key,
                  isSynched: true
                };

                log(device);
                _context7.next = 4;
                return this.masqStore.addPairedDevice(device);

              case 4:
              case 'end':
                return _context7.stop();
            }
          }
        }, _callee7, this);
      }));

      function storeRSAPublicKey(_x6, _x7) {
        return _ref7.apply(this, arguments);
      }

      return storeRSAPublicKey;
    }()
  }, {
    key: 'storeECPublicKey',
    value: function storeECPublicKey(msg) {}

    /**
     * Derive the common secret key - ECDH
     * this.EC.privateKey must exist
     * @param {string} senderECPublicKey - The hexadecimal string of of the sender EC public key
     */

  }, {
    key: 'deriveSecretKey',
    value: function () {
      var _ref8 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee8(senderECPublicKey) {
        var ECPublicKey, ECCryptoKey;
        return _regenerator2.default.wrap(function _callee8$(_context8) {
          while (1) {
            switch (_context8.prev = _context8.next) {
              case 0:
                if (this.EC.privateKey) {
                  _context8.next = 2;
                  break;
                }

                throw _masqCommon2.default.generateError(ERRORS.NOECPRIVATEKEY);

              case 2:
                ECPublicKey = _masqCrypto2.default.utils.hexStringToBuffer(senderECPublicKey);
                _context8.next = 5;
                return this.EC.importKeyRaw(ECPublicKey);

              case 5:
                ECCryptoKey = _context8.sent;
                _context8.next = 8;
                return this.EC.deriveKeyECDH(ECCryptoKey, 'aes-gcm', 128);

              case 8:
                this.commonECDHDerivedKey = _context8.sent;

              case 9:
              case 'end':
                return _context8.stop();
            }
          }
        }, _callee8, this);
      }));

      function deriveSecretKey(_x8) {
        return _ref8.apply(this, arguments);
      }

      return deriveSecretKey;
    }()

    /**
     *
     * @param {Object} data - The message data
     * @param {string} data.key - The hexadecimal string of of the sender EC public key
     * @param {string} data.signature - The hexadecimal string of the signature
     * @param {CryptoKey} senderRSAPublicKey - The RSA public key (jwt object)
     */

  }, {
    key: 'verifyReceivedECPublicKey',
    value: function () {
      var _ref9 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee9(data, senderRSAPublicKey) {
        var ECPublicKey, signature;
        return _regenerator2.default.wrap(function _callee9$(_context9) {
          while (1) {
            switch (_context9.prev = _context9.next) {
              case 0:
                ECPublicKey = _masqCrypto2.default.utils.hexStringToBuffer(data.key);
                signature = _masqCrypto2.default.utils.hexStringToBuffer(data.signature);
                return _context9.abrupt('return', _masqCrypto2.default.RSA.verifRSA(senderRSAPublicKey, signature, ECPublicKey));

              case 3:
              case 'end':
                return _context9.stop();
            }
          }
        }, _callee9, this);
      }));

      function verifyReceivedECPublicKey(_x9, _x10) {
        return _ref9.apply(this, arguments);
      }

      return verifyReceivedECPublicKey;
    }()
  }, {
    key: 'handleGroupKey',
    value: function () {
      var _ref10 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee10(msg) {
        var groupKey;
        return _regenerator2.default.wrap(function _callee10$(_context10) {
          while (1) {
            switch (_context10.prev = _context10.next) {
              case 0:
                _context10.next = 2;
                return this.decryptGroupKey(msg);

              case 2:
                groupKey = _context10.sent;

                this.emit('channelKey', { key: groupKey, from: msg.from });

              case 4:
              case 'end':
                return _context10.stop();
            }
          }
        }, _callee10, this);
      }));

      function handleGroupKey(_x11) {
        return _ref10.apply(this, arguments);
      }

      return handleGroupKey;
    }()

    /**
    * Handle the received RSA public key
    * @param {ECPublicKeyMsgFormat} msg
    */

  }, {
    key: 'handleRSAPublicKey',
    value: function () {
      var _ref11 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee11(msg) {
        var RSAPublicKey, params;
        return _regenerator2.default.wrap(function _callee11$(_context11) {
          while (1) {
            switch (_context11.prev = _context11.next) {
              case 0:
                _context11.next = 2;
                return this.decryptRSAPublicKey(msg.data.key);

              case 2:
                RSAPublicKey = _context11.sent;

                this.storeRSAPublicKey(msg.from, RSAPublicKey);
                this.emit('RSAPublicKey', { key: RSAPublicKey, from: msg.from });

                if (!msg.ack) {
                  _context11.next = 7;
                  break;
                }

                return _context11.abrupt('return');

              case 7:
                // If initial request, send the RSA public key
                params = {
                  to: msg.from,
                  ack: true
                };

                this.sendRSAPublicKey(params);

              case 9:
              case 'end':
                return _context11.stop();
            }
          }
        }, _callee11, this);
      }));

      function handleRSAPublicKey(_x12) {
        return _ref11.apply(this, arguments);
      }

      return handleRSAPublicKey;
    }()

    /**
    * Handle the received EC public key
    * @param {ECPublicKeyMsgFormat} msg
    */

  }, {
    key: 'handleECPublicKey',
    value: function () {
      var _ref12 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee12(msg) {
        var devices, senderRSAPublicKey, params;
        return _regenerator2.default.wrap(function _callee12$(_context12) {
          while (1) {
            switch (_context12.prev = _context12.next) {
              case 0:
                _context12.next = 2;
                return this.masqStore.listDevices();

              case 2:
                devices = _context12.sent;

                if (devices[msg.from].RSAPublicKey) {
                  _context12.next = 5;
                  break;
                }

                throw _masqCommon2.default.generateError(ERRORS.NORSAPUBLICKEYSTORED);

              case 5:
                _context12.next = 7;
                return _masqCrypto2.default.RSA.importRSAPubKey(JSON.parse(devices[msg.from].RSAPublicKey));

              case 7:
                senderRSAPublicKey = _context12.sent;

                if (this.verifyReceivedECPublicKey(msg.data, senderRSAPublicKey)) {
                  _context12.next = 10;
                  break;
                }

                throw _masqCommon2.default.generateError(ERRORS.VERIFICATIONFAILED);

              case 10:
                if (!msg.ack) {
                  _context12.next = 17;
                  break;
                }

                _context12.next = 13;
                return this.deriveSecretKey(msg.data.key);

              case 13:
                this.emit('initECDH', { key: this.commonECDHDerivedKey, from: msg.from });
                this.readyToTransfer(msg.from);
                _context12.next = 24;
                break;

              case 17:
                // If initial request, send EC public key
                this.EC = new _masqCrypto2.default.EC({});
                _context12.next = 20;
                return this.EC.genECKeyPair();

              case 20:
                _context12.next = 22;
                return this.deriveSecretKey(msg.data.key);

              case 22:
                params = {
                  to: msg.from,
                  ack: true
                };

                this.sendECPublicKey(params);

              case 24:
              case 'end':
                return _context12.stop();
            }
          }
        }, _callee12, this);
      }));

      function handleECPublicKey(_x13) {
        return _ref12.apply(this, arguments);
      }

      return handleECPublicKey;
    }()

    /**
     * Subscribe this client to its own channel.
     *
     * @return  {object} The WebSocket client
     */

  }, {
    key: 'subscribeSelf',
    value: function subscribeSelf() {
      var _this3 = this;

      this.myChannel = this.socket.subscribe(this.ID);

      this.myChannel.watch(function (msg) {
        log('****** RECEIVE ******');
        log('From ' + msg.from + ' : ' + msg);
        log('****** RECEIVE ******');

        if (msg.from === _this3.ID) return;
        if (msg.from) {
          log('New msg in my channel:', msg.event);
          if (msg.event === 'ping') {
            var data = {
              event: 'pong',
              from: _this3.ID
            };
            if (!_this3.channels[msg.from]) {
              // Subscribe to that user
              _this3.channels[msg.from] = {
                socket: _this3.socket.subscribe(msg.from)
              };
            }
            _this3.channels[msg.from].socket.publish(data);
            // log('Channel up with ' + msg.from)
          }
          if (msg.event === 'ECPublicKey') {
            _this3.handleECPublicKey(msg);
          }
          if (msg.event === 'readyToTransfer') {
            _this3.emit('initECDH', { key: _this3.commonECDHDerivedKey, from: msg.from });
          }
          if (msg.event === 'channelKey') {
            _this3.handleGroupKey(msg);
          }
          if (msg.event === 'publicKey') {
            _this3.handleRSAPublicKey(msg);
          }
        }
      });
    }
    /**
     * Subscribe peer to a given channel.
     *
     * @param   {string} peer A peer (device)
     * @param   {boolean} batch Whether to batch requests for increased perfomance
     * @return  {Promise} Promise resolves/rejects upon subscription or errors
     */

  }, {
    key: 'subscribePeer',
    value: function subscribePeer(peer) {
      var _this4 = this;

      var batch = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      return new Promise(function (resolve, reject) {
        if (!peer || peer.length === 0) {
          return reject(new Error('Invalid peer value'));
        }
        _this4.channels[peer] = {
          socket: _this4.socket.subscribe(peer, {
            batch: batch
          })
        };
        _this4.channels[peer].socket.on('subscribe', function () {
          _this4.channels[peer].socket.publish({
            event: 'ping',
            from: _this4.ID
          });
          return resolve();
        });
        _this4.channels[peer].socket.on('subscribeFail', function () {
          return reject(new Error('Subscribe failed'));
        });
      });
    }

    /**
     * Subscribe a list of peers to a given channel.
     *
     * @param   {array} peers List of peers (devices)
     * @return  {Promise} Promise resolves/rejects upon subscription or errors
     */

  }, {
    key: 'subscribePeers',
    value: function subscribePeers() {
      var _this5 = this;

      var peers = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : [];

      if (!Array.isArray(peers)) {
        return Promise.reject(new Error('Invalid peer list'));
      }
      var pending = [];
      peers.forEach(function (peer) {
        var sub = _this5.subscribePeer(peer, true);
        sub.catch(function () {
          // do something with err
        });
        pending.push(sub);
      });
      return Promise.all(pending);
    }

    /**
     * Unsubscribe peer from a given channel.
     *
     * @param   {string} peer A peer (device)
     * @return  {Promise} Promise resolves/rejects upon unsubscription or errors
     */

  }, {
    key: 'unsubscribePeer',
    value: function unsubscribePeer(peer) {
      var _this6 = this;

      return new Promise(function (resolve, reject) {
        if (!peer || peer.length === 0 || _this6.channels[peer] === undefined) {
          return reject(new Error('Invalid peer value'));
        }
        _this6.channels[peer].socket.unsubscribe();
        delete _this6.channels[peer];
        return resolve();
      });
    }

    /**
     * Deterministically elect a master device, by using the first element of a
     * alphabetically ordered list of peers.
     *
     * @param   {array} peers List of peers (devices)
     * @return  {string} The peer ID of the master
     */

  }, {
    key: 'electMaster',
    value: function electMaster() {
      var peers = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : [];

      peers.push(this.ID);
      peers.sort();
      return peers[0];
    }
  }]);
  return Client;
}(_events2.default);

module.exports.Client = Client;