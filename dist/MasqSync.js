(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.MasqSync = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
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
},{"babel-runtime/helpers/asyncToGenerator":8,"babel-runtime/helpers/classCallCheck":9,"babel-runtime/helpers/createClass":10,"babel-runtime/helpers/inherits":11,"babel-runtime/helpers/possibleConstructorReturn":12,"babel-runtime/regenerator":14,"events":112,"masq-common":116,"masq-crypto":120,"socketcluster-client":131}],2:[function(require,module,exports){
module.exports = { "default": require("core-js/library/fn/object/create"), __esModule: true };
},{"core-js/library/fn/object/create":20}],3:[function(require,module,exports){
module.exports = { "default": require("core-js/library/fn/object/define-property"), __esModule: true };
},{"core-js/library/fn/object/define-property":21}],4:[function(require,module,exports){
module.exports = { "default": require("core-js/library/fn/object/set-prototype-of"), __esModule: true };
},{"core-js/library/fn/object/set-prototype-of":22}],5:[function(require,module,exports){
module.exports = { "default": require("core-js/library/fn/promise"), __esModule: true };
},{"core-js/library/fn/promise":23}],6:[function(require,module,exports){
module.exports = { "default": require("core-js/library/fn/symbol"), __esModule: true };
},{"core-js/library/fn/symbol":24}],7:[function(require,module,exports){
module.exports = { "default": require("core-js/library/fn/symbol/iterator"), __esModule: true };
},{"core-js/library/fn/symbol/iterator":25}],8:[function(require,module,exports){
"use strict";

exports.__esModule = true;

var _promise = require("../core-js/promise");

var _promise2 = _interopRequireDefault(_promise);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function (fn) {
  return function () {
    var gen = fn.apply(this, arguments);
    return new _promise2.default(function (resolve, reject) {
      function step(key, arg) {
        try {
          var info = gen[key](arg);
          var value = info.value;
        } catch (error) {
          reject(error);
          return;
        }

        if (info.done) {
          resolve(value);
        } else {
          return _promise2.default.resolve(value).then(function (value) {
            step("next", value);
          }, function (err) {
            step("throw", err);
          });
        }
      }

      return step("next");
    });
  };
};
},{"../core-js/promise":5}],9:[function(require,module,exports){
"use strict";

exports.__esModule = true;

exports.default = function (instance, Constructor) {
  if (!(instance instanceof Constructor)) {
    throw new TypeError("Cannot call a class as a function");
  }
};
},{}],10:[function(require,module,exports){
"use strict";

exports.__esModule = true;

var _defineProperty = require("../core-js/object/define-property");

var _defineProperty2 = _interopRequireDefault(_defineProperty);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function () {
  function defineProperties(target, props) {
    for (var i = 0; i < props.length; i++) {
      var descriptor = props[i];
      descriptor.enumerable = descriptor.enumerable || false;
      descriptor.configurable = true;
      if ("value" in descriptor) descriptor.writable = true;
      (0, _defineProperty2.default)(target, descriptor.key, descriptor);
    }
  }

  return function (Constructor, protoProps, staticProps) {
    if (protoProps) defineProperties(Constructor.prototype, protoProps);
    if (staticProps) defineProperties(Constructor, staticProps);
    return Constructor;
  };
}();
},{"../core-js/object/define-property":3}],11:[function(require,module,exports){
"use strict";

exports.__esModule = true;

var _setPrototypeOf = require("../core-js/object/set-prototype-of");

var _setPrototypeOf2 = _interopRequireDefault(_setPrototypeOf);

var _create = require("../core-js/object/create");

var _create2 = _interopRequireDefault(_create);

var _typeof2 = require("../helpers/typeof");

var _typeof3 = _interopRequireDefault(_typeof2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function (subClass, superClass) {
  if (typeof superClass !== "function" && superClass !== null) {
    throw new TypeError("Super expression must either be null or a function, not " + (typeof superClass === "undefined" ? "undefined" : (0, _typeof3.default)(superClass)));
  }

  subClass.prototype = (0, _create2.default)(superClass && superClass.prototype, {
    constructor: {
      value: subClass,
      enumerable: false,
      writable: true,
      configurable: true
    }
  });
  if (superClass) _setPrototypeOf2.default ? (0, _setPrototypeOf2.default)(subClass, superClass) : subClass.__proto__ = superClass;
};
},{"../core-js/object/create":2,"../core-js/object/set-prototype-of":4,"../helpers/typeof":13}],12:[function(require,module,exports){
"use strict";

exports.__esModule = true;

var _typeof2 = require("../helpers/typeof");

var _typeof3 = _interopRequireDefault(_typeof2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function (self, call) {
  if (!self) {
    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
  }

  return call && ((typeof call === "undefined" ? "undefined" : (0, _typeof3.default)(call)) === "object" || typeof call === "function") ? call : self;
};
},{"../helpers/typeof":13}],13:[function(require,module,exports){
"use strict";

exports.__esModule = true;

var _iterator = require("../core-js/symbol/iterator");

var _iterator2 = _interopRequireDefault(_iterator);

var _symbol = require("../core-js/symbol");

var _symbol2 = _interopRequireDefault(_symbol);

var _typeof = typeof _symbol2.default === "function" && typeof _iterator2.default === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof _symbol2.default === "function" && obj.constructor === _symbol2.default && obj !== _symbol2.default.prototype ? "symbol" : typeof obj; };

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = typeof _symbol2.default === "function" && _typeof(_iterator2.default) === "symbol" ? function (obj) {
  return typeof obj === "undefined" ? "undefined" : _typeof(obj);
} : function (obj) {
  return obj && typeof _symbol2.default === "function" && obj.constructor === _symbol2.default && obj !== _symbol2.default.prototype ? "symbol" : typeof obj === "undefined" ? "undefined" : _typeof(obj);
};
},{"../core-js/symbol":6,"../core-js/symbol/iterator":7}],14:[function(require,module,exports){
module.exports = require("regenerator-runtime");

},{"regenerator-runtime":125}],15:[function(require,module,exports){
(function (global){
/*! http://mths.be/base64 v0.1.0 by @mathias | MIT license */
;(function(root) {

	// Detect free variables `exports`.
	var freeExports = typeof exports == 'object' && exports;

	// Detect free variable `module`.
	var freeModule = typeof module == 'object' && module &&
		module.exports == freeExports && module;

	// Detect free variable `global`, from Node.js or Browserified code, and use
	// it as `root`.
	var freeGlobal = typeof global == 'object' && global;
	if (freeGlobal.global === freeGlobal || freeGlobal.window === freeGlobal) {
		root = freeGlobal;
	}

	/*--------------------------------------------------------------------------*/

	var InvalidCharacterError = function(message) {
		this.message = message;
	};
	InvalidCharacterError.prototype = new Error;
	InvalidCharacterError.prototype.name = 'InvalidCharacterError';

	var error = function(message) {
		// Note: the error messages used throughout this file match those used by
		// the native `atob`/`btoa` implementation in Chromium.
		throw new InvalidCharacterError(message);
	};

	var TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	// http://whatwg.org/html/common-microsyntaxes.html#space-character
	var REGEX_SPACE_CHARACTERS = /[\t\n\f\r ]/g;

	// `decode` is designed to be fully compatible with `atob` as described in the
	// HTML Standard. http://whatwg.org/html/webappapis.html#dom-windowbase64-atob
	// The optimized base64-decoding algorithm used is based on @atk’s excellent
	// implementation. https://gist.github.com/atk/1020396
	var decode = function(input) {
		input = String(input)
			.replace(REGEX_SPACE_CHARACTERS, '');
		var length = input.length;
		if (length % 4 == 0) {
			input = input.replace(/==?$/, '');
			length = input.length;
		}
		if (
			length % 4 == 1 ||
			// http://whatwg.org/C#alphanumeric-ascii-characters
			/[^+a-zA-Z0-9/]/.test(input)
		) {
			error(
				'Invalid character: the string to be decoded is not correctly encoded.'
			);
		}
		var bitCounter = 0;
		var bitStorage;
		var buffer;
		var output = '';
		var position = -1;
		while (++position < length) {
			buffer = TABLE.indexOf(input.charAt(position));
			bitStorage = bitCounter % 4 ? bitStorage * 64 + buffer : buffer;
			// Unless this is the first of a group of 4 characters…
			if (bitCounter++ % 4) {
				// …convert the first 8 bits to a single ASCII character.
				output += String.fromCharCode(
					0xFF & bitStorage >> (-2 * bitCounter & 6)
				);
			}
		}
		return output;
	};

	// `encode` is designed to be fully compatible with `btoa` as described in the
	// HTML Standard: http://whatwg.org/html/webappapis.html#dom-windowbase64-btoa
	var encode = function(input) {
		input = String(input);
		if (/[^\0-\xFF]/.test(input)) {
			// Note: no need to special-case astral symbols here, as surrogates are
			// matched, and the input is supposed to only contain ASCII anyway.
			error(
				'The string to be encoded contains characters outside of the ' +
				'Latin1 range.'
			);
		}
		var padding = input.length % 3;
		var output = '';
		var position = -1;
		var a;
		var b;
		var c;
		var d;
		var buffer;
		// Make sure any padding is handled outside of the loop.
		var length = input.length - padding;

		while (++position < length) {
			// Read three bytes, i.e. 24 bits.
			a = input.charCodeAt(position) << 16;
			b = input.charCodeAt(++position) << 8;
			c = input.charCodeAt(++position);
			buffer = a + b + c;
			// Turn the 24 bits into four chunks of 6 bits each, and append the
			// matching character for each of them to the output.
			output += (
				TABLE.charAt(buffer >> 18 & 0x3F) +
				TABLE.charAt(buffer >> 12 & 0x3F) +
				TABLE.charAt(buffer >> 6 & 0x3F) +
				TABLE.charAt(buffer & 0x3F)
			);
		}

		if (padding == 2) {
			a = input.charCodeAt(position) << 8;
			b = input.charCodeAt(++position);
			buffer = a + b;
			output += (
				TABLE.charAt(buffer >> 10) +
				TABLE.charAt((buffer >> 4) & 0x3F) +
				TABLE.charAt((buffer << 2) & 0x3F) +
				'='
			);
		} else if (padding == 1) {
			buffer = input.charCodeAt(position);
			output += (
				TABLE.charAt(buffer >> 2) +
				TABLE.charAt((buffer << 4) & 0x3F) +
				'=='
			);
		}

		return output;
	};

	var base64 = {
		'encode': encode,
		'decode': decode,
		'version': '0.1.0'
	};

	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (
		typeof define == 'function' &&
		typeof define.amd == 'object' &&
		define.amd
	) {
		define(function() {
			return base64;
		});
	}	else if (freeExports && !freeExports.nodeType) {
		if (freeModule) { // in Node.js or RingoJS v0.8.0+
			freeModule.exports = base64;
		} else { // in Narwhal or RingoJS v0.7.0-
			for (var key in base64) {
				base64.hasOwnProperty(key) && (freeExports[key] = base64[key]);
			}
		}
	} else { // in Rhino or a web browser
		root.base64 = base64;
	}

}(this));

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],16:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  for (var i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(
      uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)
    ))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],17:[function(require,module,exports){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = { __proto__: Uint8Array.prototype, foo: function () { return 42 } }
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species != null &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayLike(value)
  }

  if (value == null) {
    throw TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      buf = Buffer.from(buf)
    }
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
        : (firstByte > 0xBF) ? 2
          : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (var i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

},{"base64-js":16,"ieee754":113}],18:[function(require,module,exports){
(function (Buffer){
var clone = (function() {
'use strict';

function _instanceof(obj, type) {
  return type != null && obj instanceof type;
}

var nativeMap;
try {
  nativeMap = Map;
} catch(_) {
  // maybe a reference error because no `Map`. Give it a dummy value that no
  // value will ever be an instanceof.
  nativeMap = function() {};
}

var nativeSet;
try {
  nativeSet = Set;
} catch(_) {
  nativeSet = function() {};
}

var nativePromise;
try {
  nativePromise = Promise;
} catch(_) {
  nativePromise = function() {};
}

/**
 * Clones (copies) an Object using deep copying.
 *
 * This function supports circular references by default, but if you are certain
 * there are no circular references in your object, you can save some CPU time
 * by calling clone(obj, false).
 *
 * Caution: if `circular` is false and `parent` contains circular references,
 * your program may enter an infinite loop and crash.
 *
 * @param `parent` - the object to be cloned
 * @param `circular` - set to true if the object to be cloned may contain
 *    circular references. (optional - true by default)
 * @param `depth` - set to a number if the object is only to be cloned to
 *    a particular depth. (optional - defaults to Infinity)
 * @param `prototype` - sets the prototype to be used when cloning an object.
 *    (optional - defaults to parent prototype).
 * @param `includeNonEnumerable` - set to true if the non-enumerable properties
 *    should be cloned as well. Non-enumerable properties on the prototype
 *    chain will be ignored. (optional - false by default)
*/
function clone(parent, circular, depth, prototype, includeNonEnumerable) {
  if (typeof circular === 'object') {
    depth = circular.depth;
    prototype = circular.prototype;
    includeNonEnumerable = circular.includeNonEnumerable;
    circular = circular.circular;
  }
  // maintain two arrays for circular references, where corresponding parents
  // and children have the same index
  var allParents = [];
  var allChildren = [];

  var useBuffer = typeof Buffer != 'undefined';

  if (typeof circular == 'undefined')
    circular = true;

  if (typeof depth == 'undefined')
    depth = Infinity;

  // recurse this function so we don't reset allParents and allChildren
  function _clone(parent, depth) {
    // cloning null always returns null
    if (parent === null)
      return null;

    if (depth === 0)
      return parent;

    var child;
    var proto;
    if (typeof parent != 'object') {
      return parent;
    }

    if (_instanceof(parent, nativeMap)) {
      child = new nativeMap();
    } else if (_instanceof(parent, nativeSet)) {
      child = new nativeSet();
    } else if (_instanceof(parent, nativePromise)) {
      child = new nativePromise(function (resolve, reject) {
        parent.then(function(value) {
          resolve(_clone(value, depth - 1));
        }, function(err) {
          reject(_clone(err, depth - 1));
        });
      });
    } else if (clone.__isArray(parent)) {
      child = [];
    } else if (clone.__isRegExp(parent)) {
      child = new RegExp(parent.source, __getRegExpFlags(parent));
      if (parent.lastIndex) child.lastIndex = parent.lastIndex;
    } else if (clone.__isDate(parent)) {
      child = new Date(parent.getTime());
    } else if (useBuffer && Buffer.isBuffer(parent)) {
      child = new Buffer(parent.length);
      parent.copy(child);
      return child;
    } else if (_instanceof(parent, Error)) {
      child = Object.create(parent);
    } else {
      if (typeof prototype == 'undefined') {
        proto = Object.getPrototypeOf(parent);
        child = Object.create(proto);
      }
      else {
        child = Object.create(prototype);
        proto = prototype;
      }
    }

    if (circular) {
      var index = allParents.indexOf(parent);

      if (index != -1) {
        return allChildren[index];
      }
      allParents.push(parent);
      allChildren.push(child);
    }

    if (_instanceof(parent, nativeMap)) {
      parent.forEach(function(value, key) {
        var keyChild = _clone(key, depth - 1);
        var valueChild = _clone(value, depth - 1);
        child.set(keyChild, valueChild);
      });
    }
    if (_instanceof(parent, nativeSet)) {
      parent.forEach(function(value) {
        var entryChild = _clone(value, depth - 1);
        child.add(entryChild);
      });
    }

    for (var i in parent) {
      var attrs;
      if (proto) {
        attrs = Object.getOwnPropertyDescriptor(proto, i);
      }

      if (attrs && attrs.set == null) {
        continue;
      }
      child[i] = _clone(parent[i], depth - 1);
    }

    if (Object.getOwnPropertySymbols) {
      var symbols = Object.getOwnPropertySymbols(parent);
      for (var i = 0; i < symbols.length; i++) {
        // Don't need to worry about cloning a symbol because it is a primitive,
        // like a number or string.
        var symbol = symbols[i];
        var descriptor = Object.getOwnPropertyDescriptor(parent, symbol);
        if (descriptor && !descriptor.enumerable && !includeNonEnumerable) {
          continue;
        }
        child[symbol] = _clone(parent[symbol], depth - 1);
        if (!descriptor.enumerable) {
          Object.defineProperty(child, symbol, {
            enumerable: false
          });
        }
      }
    }

    if (includeNonEnumerable) {
      var allPropertyNames = Object.getOwnPropertyNames(parent);
      for (var i = 0; i < allPropertyNames.length; i++) {
        var propertyName = allPropertyNames[i];
        var descriptor = Object.getOwnPropertyDescriptor(parent, propertyName);
        if (descriptor && descriptor.enumerable) {
          continue;
        }
        child[propertyName] = _clone(parent[propertyName], depth - 1);
        Object.defineProperty(child, propertyName, {
          enumerable: false
        });
      }
    }

    return child;
  }

  return _clone(parent, depth);
}

/**
 * Simple flat clone using prototype, accepts only objects, usefull for property
 * override on FLAT configuration object (no nested props).
 *
 * USE WITH CAUTION! This may not behave as you wish if you do not know how this
 * works.
 */
clone.clonePrototype = function clonePrototype(parent) {
  if (parent === null)
    return null;

  var c = function () {};
  c.prototype = parent;
  return new c();
};

// private utility functions

function __objToStr(o) {
  return Object.prototype.toString.call(o);
}
clone.__objToStr = __objToStr;

function __isDate(o) {
  return typeof o === 'object' && __objToStr(o) === '[object Date]';
}
clone.__isDate = __isDate;

function __isArray(o) {
  return typeof o === 'object' && __objToStr(o) === '[object Array]';
}
clone.__isArray = __isArray;

function __isRegExp(o) {
  return typeof o === 'object' && __objToStr(o) === '[object RegExp]';
}
clone.__isRegExp = __isRegExp;

function __getRegExpFlags(re) {
  var flags = '';
  if (re.global) flags += 'g';
  if (re.ignoreCase) flags += 'i';
  if (re.multiline) flags += 'm';
  return flags;
}
clone.__getRegExpFlags = __getRegExpFlags;

return clone;
})();

if (typeof module === 'object' && module.exports) {
  module.exports = clone;
}

}).call(this,require("buffer").Buffer)
},{"buffer":17}],19:[function(require,module,exports){

/**
 * Expose `Emitter`.
 */

if (typeof module !== 'undefined') {
  module.exports = Emitter;
}

/**
 * Initialize a new `Emitter`.
 *
 * @api public
 */

function Emitter(obj) {
  if (obj) return mixin(obj);
};

/**
 * Mixin the emitter properties.
 *
 * @param {Object} obj
 * @return {Object}
 * @api private
 */

function mixin(obj) {
  for (var key in Emitter.prototype) {
    obj[key] = Emitter.prototype[key];
  }
  return obj;
}

/**
 * Listen on the given `event` with `fn`.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.on =
Emitter.prototype.addEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};
  (this._callbacks['$' + event] = this._callbacks['$' + event] || [])
    .push(fn);
  return this;
};

/**
 * Adds an `event` listener that will be invoked a single
 * time then automatically removed.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.once = function(event, fn){
  function on() {
    this.off(event, on);
    fn.apply(this, arguments);
  }

  on.fn = fn;
  this.on(event, on);
  return this;
};

/**
 * Remove the given callback for `event` or all
 * registered callbacks.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.off =
Emitter.prototype.removeListener =
Emitter.prototype.removeAllListeners =
Emitter.prototype.removeEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};

  // all
  if (0 == arguments.length) {
    this._callbacks = {};
    return this;
  }

  // specific event
  var callbacks = this._callbacks['$' + event];
  if (!callbacks) return this;

  // remove all handlers
  if (1 == arguments.length) {
    delete this._callbacks['$' + event];
    return this;
  }

  // remove specific handler
  var cb;
  for (var i = 0; i < callbacks.length; i++) {
    cb = callbacks[i];
    if (cb === fn || cb.fn === fn) {
      callbacks.splice(i, 1);
      break;
    }
  }
  return this;
};

/**
 * Emit `event` with the given args.
 *
 * @param {String} event
 * @param {Mixed} ...
 * @return {Emitter}
 */

Emitter.prototype.emit = function(event){
  this._callbacks = this._callbacks || {};
  var args = [].slice.call(arguments, 1)
    , callbacks = this._callbacks['$' + event];

  if (callbacks) {
    callbacks = callbacks.slice(0);
    for (var i = 0, len = callbacks.length; i < len; ++i) {
      callbacks[i].apply(this, args);
    }
  }

  return this;
};

/**
 * Return array of callbacks for `event`.
 *
 * @param {String} event
 * @return {Array}
 * @api public
 */

Emitter.prototype.listeners = function(event){
  this._callbacks = this._callbacks || {};
  return this._callbacks['$' + event] || [];
};

/**
 * Check if this emitter has `event` handlers.
 *
 * @param {String} event
 * @return {Boolean}
 * @api public
 */

Emitter.prototype.hasListeners = function(event){
  return !! this.listeners(event).length;
};

},{}],20:[function(require,module,exports){
require('../../modules/es6.object.create');
var $Object = require('../../modules/_core').Object;
module.exports = function create(P, D) {
  return $Object.create(P, D);
};

},{"../../modules/_core":33,"../../modules/es6.object.create":100}],21:[function(require,module,exports){
require('../../modules/es6.object.define-property');
var $Object = require('../../modules/_core').Object;
module.exports = function defineProperty(it, key, desc) {
  return $Object.defineProperty(it, key, desc);
};

},{"../../modules/_core":33,"../../modules/es6.object.define-property":101}],22:[function(require,module,exports){
require('../../modules/es6.object.set-prototype-of');
module.exports = require('../../modules/_core').Object.setPrototypeOf;

},{"../../modules/_core":33,"../../modules/es6.object.set-prototype-of":102}],23:[function(require,module,exports){
require('../modules/es6.object.to-string');
require('../modules/es6.string.iterator');
require('../modules/web.dom.iterable');
require('../modules/es6.promise');
require('../modules/es7.promise.finally');
require('../modules/es7.promise.try');
module.exports = require('../modules/_core').Promise;

},{"../modules/_core":33,"../modules/es6.object.to-string":103,"../modules/es6.promise":104,"../modules/es6.string.iterator":105,"../modules/es7.promise.finally":107,"../modules/es7.promise.try":108,"../modules/web.dom.iterable":111}],24:[function(require,module,exports){
require('../../modules/es6.symbol');
require('../../modules/es6.object.to-string');
require('../../modules/es7.symbol.async-iterator');
require('../../modules/es7.symbol.observable');
module.exports = require('../../modules/_core').Symbol;

},{"../../modules/_core":33,"../../modules/es6.object.to-string":103,"../../modules/es6.symbol":106,"../../modules/es7.symbol.async-iterator":109,"../../modules/es7.symbol.observable":110}],25:[function(require,module,exports){
require('../../modules/es6.string.iterator');
require('../../modules/web.dom.iterable');
module.exports = require('../../modules/_wks-ext').f('iterator');

},{"../../modules/_wks-ext":96,"../../modules/es6.string.iterator":105,"../../modules/web.dom.iterable":111}],26:[function(require,module,exports){
module.exports = function (it) {
  if (typeof it != 'function') throw TypeError(it + ' is not a function!');
  return it;
};

},{}],27:[function(require,module,exports){
module.exports = function () { /* empty */ };

},{}],28:[function(require,module,exports){
module.exports = function (it, Constructor, name, forbiddenField) {
  if (!(it instanceof Constructor) || (forbiddenField !== undefined && forbiddenField in it)) {
    throw TypeError(name + ': incorrect invocation!');
  } return it;
};

},{}],29:[function(require,module,exports){
var isObject = require('./_is-object');
module.exports = function (it) {
  if (!isObject(it)) throw TypeError(it + ' is not an object!');
  return it;
};

},{"./_is-object":52}],30:[function(require,module,exports){
// false -> Array#indexOf
// true  -> Array#includes
var toIObject = require('./_to-iobject');
var toLength = require('./_to-length');
var toAbsoluteIndex = require('./_to-absolute-index');
module.exports = function (IS_INCLUDES) {
  return function ($this, el, fromIndex) {
    var O = toIObject($this);
    var length = toLength(O.length);
    var index = toAbsoluteIndex(fromIndex, length);
    var value;
    // Array#includes uses SameValueZero equality algorithm
    // eslint-disable-next-line no-self-compare
    if (IS_INCLUDES && el != el) while (length > index) {
      value = O[index++];
      // eslint-disable-next-line no-self-compare
      if (value != value) return true;
    // Array#indexOf ignores holes, Array#includes - not
    } else for (;length > index; index++) if (IS_INCLUDES || index in O) {
      if (O[index] === el) return IS_INCLUDES || index || 0;
    } return !IS_INCLUDES && -1;
  };
};

},{"./_to-absolute-index":87,"./_to-iobject":89,"./_to-length":90}],31:[function(require,module,exports){
// getting tag from 19.1.3.6 Object.prototype.toString()
var cof = require('./_cof');
var TAG = require('./_wks')('toStringTag');
// ES3 wrong here
var ARG = cof(function () { return arguments; }()) == 'Arguments';

// fallback for IE11 Script Access Denied error
var tryGet = function (it, key) {
  try {
    return it[key];
  } catch (e) { /* empty */ }
};

module.exports = function (it) {
  var O, T, B;
  return it === undefined ? 'Undefined' : it === null ? 'Null'
    // @@toStringTag case
    : typeof (T = tryGet(O = Object(it), TAG)) == 'string' ? T
    // builtinTag case
    : ARG ? cof(O)
    // ES3 arguments fallback
    : (B = cof(O)) == 'Object' && typeof O.callee == 'function' ? 'Arguments' : B;
};

},{"./_cof":32,"./_wks":97}],32:[function(require,module,exports){
var toString = {}.toString;

module.exports = function (it) {
  return toString.call(it).slice(8, -1);
};

},{}],33:[function(require,module,exports){
var core = module.exports = { version: '2.5.7' };
if (typeof __e == 'number') __e = core; // eslint-disable-line no-undef

},{}],34:[function(require,module,exports){
// optional / simple context binding
var aFunction = require('./_a-function');
module.exports = function (fn, that, length) {
  aFunction(fn);
  if (that === undefined) return fn;
  switch (length) {
    case 1: return function (a) {
      return fn.call(that, a);
    };
    case 2: return function (a, b) {
      return fn.call(that, a, b);
    };
    case 3: return function (a, b, c) {
      return fn.call(that, a, b, c);
    };
  }
  return function (/* ...args */) {
    return fn.apply(that, arguments);
  };
};

},{"./_a-function":26}],35:[function(require,module,exports){
// 7.2.1 RequireObjectCoercible(argument)
module.exports = function (it) {
  if (it == undefined) throw TypeError("Can't call method on  " + it);
  return it;
};

},{}],36:[function(require,module,exports){
// Thank's IE8 for his funny defineProperty
module.exports = !require('./_fails')(function () {
  return Object.defineProperty({}, 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_fails":41}],37:[function(require,module,exports){
var isObject = require('./_is-object');
var document = require('./_global').document;
// typeof document.createElement is 'object' in old IE
var is = isObject(document) && isObject(document.createElement);
module.exports = function (it) {
  return is ? document.createElement(it) : {};
};

},{"./_global":43,"./_is-object":52}],38:[function(require,module,exports){
// IE 8- don't enum bug keys
module.exports = (
  'constructor,hasOwnProperty,isPrototypeOf,propertyIsEnumerable,toLocaleString,toString,valueOf'
).split(',');

},{}],39:[function(require,module,exports){
// all enumerable object keys, includes symbols
var getKeys = require('./_object-keys');
var gOPS = require('./_object-gops');
var pIE = require('./_object-pie');
module.exports = function (it) {
  var result = getKeys(it);
  var getSymbols = gOPS.f;
  if (getSymbols) {
    var symbols = getSymbols(it);
    var isEnum = pIE.f;
    var i = 0;
    var key;
    while (symbols.length > i) if (isEnum.call(it, key = symbols[i++])) result.push(key);
  } return result;
};

},{"./_object-gops":69,"./_object-keys":72,"./_object-pie":73}],40:[function(require,module,exports){
var global = require('./_global');
var core = require('./_core');
var ctx = require('./_ctx');
var hide = require('./_hide');
var has = require('./_has');
var PROTOTYPE = 'prototype';

var $export = function (type, name, source) {
  var IS_FORCED = type & $export.F;
  var IS_GLOBAL = type & $export.G;
  var IS_STATIC = type & $export.S;
  var IS_PROTO = type & $export.P;
  var IS_BIND = type & $export.B;
  var IS_WRAP = type & $export.W;
  var exports = IS_GLOBAL ? core : core[name] || (core[name] = {});
  var expProto = exports[PROTOTYPE];
  var target = IS_GLOBAL ? global : IS_STATIC ? global[name] : (global[name] || {})[PROTOTYPE];
  var key, own, out;
  if (IS_GLOBAL) source = name;
  for (key in source) {
    // contains in native
    own = !IS_FORCED && target && target[key] !== undefined;
    if (own && has(exports, key)) continue;
    // export native or passed
    out = own ? target[key] : source[key];
    // prevent global pollution for namespaces
    exports[key] = IS_GLOBAL && typeof target[key] != 'function' ? source[key]
    // bind timers to global for call from export context
    : IS_BIND && own ? ctx(out, global)
    // wrap global constructors for prevent change them in library
    : IS_WRAP && target[key] == out ? (function (C) {
      var F = function (a, b, c) {
        if (this instanceof C) {
          switch (arguments.length) {
            case 0: return new C();
            case 1: return new C(a);
            case 2: return new C(a, b);
          } return new C(a, b, c);
        } return C.apply(this, arguments);
      };
      F[PROTOTYPE] = C[PROTOTYPE];
      return F;
    // make static versions for prototype methods
    })(out) : IS_PROTO && typeof out == 'function' ? ctx(Function.call, out) : out;
    // export proto methods to core.%CONSTRUCTOR%.methods.%NAME%
    if (IS_PROTO) {
      (exports.virtual || (exports.virtual = {}))[key] = out;
      // export proto methods to core.%CONSTRUCTOR%.prototype.%NAME%
      if (type & $export.R && expProto && !expProto[key]) hide(expProto, key, out);
    }
  }
};
// type bitmap
$export.F = 1;   // forced
$export.G = 2;   // global
$export.S = 4;   // static
$export.P = 8;   // proto
$export.B = 16;  // bind
$export.W = 32;  // wrap
$export.U = 64;  // safe
$export.R = 128; // real proto method for `library`
module.exports = $export;

},{"./_core":33,"./_ctx":34,"./_global":43,"./_has":44,"./_hide":45}],41:[function(require,module,exports){
module.exports = function (exec) {
  try {
    return !!exec();
  } catch (e) {
    return true;
  }
};

},{}],42:[function(require,module,exports){
var ctx = require('./_ctx');
var call = require('./_iter-call');
var isArrayIter = require('./_is-array-iter');
var anObject = require('./_an-object');
var toLength = require('./_to-length');
var getIterFn = require('./core.get-iterator-method');
var BREAK = {};
var RETURN = {};
var exports = module.exports = function (iterable, entries, fn, that, ITERATOR) {
  var iterFn = ITERATOR ? function () { return iterable; } : getIterFn(iterable);
  var f = ctx(fn, that, entries ? 2 : 1);
  var index = 0;
  var length, step, iterator, result;
  if (typeof iterFn != 'function') throw TypeError(iterable + ' is not iterable!');
  // fast case for arrays with default iterator
  if (isArrayIter(iterFn)) for (length = toLength(iterable.length); length > index; index++) {
    result = entries ? f(anObject(step = iterable[index])[0], step[1]) : f(iterable[index]);
    if (result === BREAK || result === RETURN) return result;
  } else for (iterator = iterFn.call(iterable); !(step = iterator.next()).done;) {
    result = call(iterator, f, step.value, entries);
    if (result === BREAK || result === RETURN) return result;
  }
};
exports.BREAK = BREAK;
exports.RETURN = RETURN;

},{"./_an-object":29,"./_ctx":34,"./_is-array-iter":50,"./_iter-call":53,"./_to-length":90,"./core.get-iterator-method":98}],43:[function(require,module,exports){
// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
var global = module.exports = typeof window != 'undefined' && window.Math == Math
  ? window : typeof self != 'undefined' && self.Math == Math ? self
  // eslint-disable-next-line no-new-func
  : Function('return this')();
if (typeof __g == 'number') __g = global; // eslint-disable-line no-undef

},{}],44:[function(require,module,exports){
var hasOwnProperty = {}.hasOwnProperty;
module.exports = function (it, key) {
  return hasOwnProperty.call(it, key);
};

},{}],45:[function(require,module,exports){
var dP = require('./_object-dp');
var createDesc = require('./_property-desc');
module.exports = require('./_descriptors') ? function (object, key, value) {
  return dP.f(object, key, createDesc(1, value));
} : function (object, key, value) {
  object[key] = value;
  return object;
};

},{"./_descriptors":36,"./_object-dp":64,"./_property-desc":76}],46:[function(require,module,exports){
var document = require('./_global').document;
module.exports = document && document.documentElement;

},{"./_global":43}],47:[function(require,module,exports){
module.exports = !require('./_descriptors') && !require('./_fails')(function () {
  return Object.defineProperty(require('./_dom-create')('div'), 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_descriptors":36,"./_dom-create":37,"./_fails":41}],48:[function(require,module,exports){
// fast apply, http://jsperf.lnkit.com/fast-apply/5
module.exports = function (fn, args, that) {
  var un = that === undefined;
  switch (args.length) {
    case 0: return un ? fn()
                      : fn.call(that);
    case 1: return un ? fn(args[0])
                      : fn.call(that, args[0]);
    case 2: return un ? fn(args[0], args[1])
                      : fn.call(that, args[0], args[1]);
    case 3: return un ? fn(args[0], args[1], args[2])
                      : fn.call(that, args[0], args[1], args[2]);
    case 4: return un ? fn(args[0], args[1], args[2], args[3])
                      : fn.call(that, args[0], args[1], args[2], args[3]);
  } return fn.apply(that, args);
};

},{}],49:[function(require,module,exports){
// fallback for non-array-like ES3 and non-enumerable old V8 strings
var cof = require('./_cof');
// eslint-disable-next-line no-prototype-builtins
module.exports = Object('z').propertyIsEnumerable(0) ? Object : function (it) {
  return cof(it) == 'String' ? it.split('') : Object(it);
};

},{"./_cof":32}],50:[function(require,module,exports){
// check on default Array iterator
var Iterators = require('./_iterators');
var ITERATOR = require('./_wks')('iterator');
var ArrayProto = Array.prototype;

module.exports = function (it) {
  return it !== undefined && (Iterators.Array === it || ArrayProto[ITERATOR] === it);
};

},{"./_iterators":58,"./_wks":97}],51:[function(require,module,exports){
// 7.2.2 IsArray(argument)
var cof = require('./_cof');
module.exports = Array.isArray || function isArray(arg) {
  return cof(arg) == 'Array';
};

},{"./_cof":32}],52:[function(require,module,exports){
module.exports = function (it) {
  return typeof it === 'object' ? it !== null : typeof it === 'function';
};

},{}],53:[function(require,module,exports){
// call something on iterator step with safe closing on error
var anObject = require('./_an-object');
module.exports = function (iterator, fn, value, entries) {
  try {
    return entries ? fn(anObject(value)[0], value[1]) : fn(value);
  // 7.4.6 IteratorClose(iterator, completion)
  } catch (e) {
    var ret = iterator['return'];
    if (ret !== undefined) anObject(ret.call(iterator));
    throw e;
  }
};

},{"./_an-object":29}],54:[function(require,module,exports){
'use strict';
var create = require('./_object-create');
var descriptor = require('./_property-desc');
var setToStringTag = require('./_set-to-string-tag');
var IteratorPrototype = {};

// 25.1.2.1.1 %IteratorPrototype%[@@iterator]()
require('./_hide')(IteratorPrototype, require('./_wks')('iterator'), function () { return this; });

module.exports = function (Constructor, NAME, next) {
  Constructor.prototype = create(IteratorPrototype, { next: descriptor(1, next) });
  setToStringTag(Constructor, NAME + ' Iterator');
};

},{"./_hide":45,"./_object-create":63,"./_property-desc":76,"./_set-to-string-tag":81,"./_wks":97}],55:[function(require,module,exports){
'use strict';
var LIBRARY = require('./_library');
var $export = require('./_export');
var redefine = require('./_redefine');
var hide = require('./_hide');
var Iterators = require('./_iterators');
var $iterCreate = require('./_iter-create');
var setToStringTag = require('./_set-to-string-tag');
var getPrototypeOf = require('./_object-gpo');
var ITERATOR = require('./_wks')('iterator');
var BUGGY = !([].keys && 'next' in [].keys()); // Safari has buggy iterators w/o `next`
var FF_ITERATOR = '@@iterator';
var KEYS = 'keys';
var VALUES = 'values';

var returnThis = function () { return this; };

module.exports = function (Base, NAME, Constructor, next, DEFAULT, IS_SET, FORCED) {
  $iterCreate(Constructor, NAME, next);
  var getMethod = function (kind) {
    if (!BUGGY && kind in proto) return proto[kind];
    switch (kind) {
      case KEYS: return function keys() { return new Constructor(this, kind); };
      case VALUES: return function values() { return new Constructor(this, kind); };
    } return function entries() { return new Constructor(this, kind); };
  };
  var TAG = NAME + ' Iterator';
  var DEF_VALUES = DEFAULT == VALUES;
  var VALUES_BUG = false;
  var proto = Base.prototype;
  var $native = proto[ITERATOR] || proto[FF_ITERATOR] || DEFAULT && proto[DEFAULT];
  var $default = $native || getMethod(DEFAULT);
  var $entries = DEFAULT ? !DEF_VALUES ? $default : getMethod('entries') : undefined;
  var $anyNative = NAME == 'Array' ? proto.entries || $native : $native;
  var methods, key, IteratorPrototype;
  // Fix native
  if ($anyNative) {
    IteratorPrototype = getPrototypeOf($anyNative.call(new Base()));
    if (IteratorPrototype !== Object.prototype && IteratorPrototype.next) {
      // Set @@toStringTag to native iterators
      setToStringTag(IteratorPrototype, TAG, true);
      // fix for some old engines
      if (!LIBRARY && typeof IteratorPrototype[ITERATOR] != 'function') hide(IteratorPrototype, ITERATOR, returnThis);
    }
  }
  // fix Array#{values, @@iterator}.name in V8 / FF
  if (DEF_VALUES && $native && $native.name !== VALUES) {
    VALUES_BUG = true;
    $default = function values() { return $native.call(this); };
  }
  // Define iterator
  if ((!LIBRARY || FORCED) && (BUGGY || VALUES_BUG || !proto[ITERATOR])) {
    hide(proto, ITERATOR, $default);
  }
  // Plug for library
  Iterators[NAME] = $default;
  Iterators[TAG] = returnThis;
  if (DEFAULT) {
    methods = {
      values: DEF_VALUES ? $default : getMethod(VALUES),
      keys: IS_SET ? $default : getMethod(KEYS),
      entries: $entries
    };
    if (FORCED) for (key in methods) {
      if (!(key in proto)) redefine(proto, key, methods[key]);
    } else $export($export.P + $export.F * (BUGGY || VALUES_BUG), NAME, methods);
  }
  return methods;
};

},{"./_export":40,"./_hide":45,"./_iter-create":54,"./_iterators":58,"./_library":59,"./_object-gpo":70,"./_redefine":78,"./_set-to-string-tag":81,"./_wks":97}],56:[function(require,module,exports){
var ITERATOR = require('./_wks')('iterator');
var SAFE_CLOSING = false;

try {
  var riter = [7][ITERATOR]();
  riter['return'] = function () { SAFE_CLOSING = true; };
  // eslint-disable-next-line no-throw-literal
  Array.from(riter, function () { throw 2; });
} catch (e) { /* empty */ }

module.exports = function (exec, skipClosing) {
  if (!skipClosing && !SAFE_CLOSING) return false;
  var safe = false;
  try {
    var arr = [7];
    var iter = arr[ITERATOR]();
    iter.next = function () { return { done: safe = true }; };
    arr[ITERATOR] = function () { return iter; };
    exec(arr);
  } catch (e) { /* empty */ }
  return safe;
};

},{"./_wks":97}],57:[function(require,module,exports){
module.exports = function (done, value) {
  return { value: value, done: !!done };
};

},{}],58:[function(require,module,exports){
module.exports = {};

},{}],59:[function(require,module,exports){
module.exports = true;

},{}],60:[function(require,module,exports){
var META = require('./_uid')('meta');
var isObject = require('./_is-object');
var has = require('./_has');
var setDesc = require('./_object-dp').f;
var id = 0;
var isExtensible = Object.isExtensible || function () {
  return true;
};
var FREEZE = !require('./_fails')(function () {
  return isExtensible(Object.preventExtensions({}));
});
var setMeta = function (it) {
  setDesc(it, META, { value: {
    i: 'O' + ++id, // object ID
    w: {}          // weak collections IDs
  } });
};
var fastKey = function (it, create) {
  // return primitive with prefix
  if (!isObject(it)) return typeof it == 'symbol' ? it : (typeof it == 'string' ? 'S' : 'P') + it;
  if (!has(it, META)) {
    // can't set metadata to uncaught frozen object
    if (!isExtensible(it)) return 'F';
    // not necessary to add metadata
    if (!create) return 'E';
    // add missing metadata
    setMeta(it);
  // return object ID
  } return it[META].i;
};
var getWeak = function (it, create) {
  if (!has(it, META)) {
    // can't set metadata to uncaught frozen object
    if (!isExtensible(it)) return true;
    // not necessary to add metadata
    if (!create) return false;
    // add missing metadata
    setMeta(it);
  // return hash weak collections IDs
  } return it[META].w;
};
// add metadata on freeze-family methods calling
var onFreeze = function (it) {
  if (FREEZE && meta.NEED && isExtensible(it) && !has(it, META)) setMeta(it);
  return it;
};
var meta = module.exports = {
  KEY: META,
  NEED: false,
  fastKey: fastKey,
  getWeak: getWeak,
  onFreeze: onFreeze
};

},{"./_fails":41,"./_has":44,"./_is-object":52,"./_object-dp":64,"./_uid":93}],61:[function(require,module,exports){
var global = require('./_global');
var macrotask = require('./_task').set;
var Observer = global.MutationObserver || global.WebKitMutationObserver;
var process = global.process;
var Promise = global.Promise;
var isNode = require('./_cof')(process) == 'process';

module.exports = function () {
  var head, last, notify;

  var flush = function () {
    var parent, fn;
    if (isNode && (parent = process.domain)) parent.exit();
    while (head) {
      fn = head.fn;
      head = head.next;
      try {
        fn();
      } catch (e) {
        if (head) notify();
        else last = undefined;
        throw e;
      }
    } last = undefined;
    if (parent) parent.enter();
  };

  // Node.js
  if (isNode) {
    notify = function () {
      process.nextTick(flush);
    };
  // browsers with MutationObserver, except iOS Safari - https://github.com/zloirock/core-js/issues/339
  } else if (Observer && !(global.navigator && global.navigator.standalone)) {
    var toggle = true;
    var node = document.createTextNode('');
    new Observer(flush).observe(node, { characterData: true }); // eslint-disable-line no-new
    notify = function () {
      node.data = toggle = !toggle;
    };
  // environments with maybe non-completely correct, but existent Promise
  } else if (Promise && Promise.resolve) {
    // Promise.resolve without an argument throws an error in LG WebOS 2
    var promise = Promise.resolve(undefined);
    notify = function () {
      promise.then(flush);
    };
  // for other environments - macrotask based on:
  // - setImmediate
  // - MessageChannel
  // - window.postMessag
  // - onreadystatechange
  // - setTimeout
  } else {
    notify = function () {
      // strange IE + webpack dev server bug - use .call(global)
      macrotask.call(global, flush);
    };
  }

  return function (fn) {
    var task = { fn: fn, next: undefined };
    if (last) last.next = task;
    if (!head) {
      head = task;
      notify();
    } last = task;
  };
};

},{"./_cof":32,"./_global":43,"./_task":86}],62:[function(require,module,exports){
'use strict';
// 25.4.1.5 NewPromiseCapability(C)
var aFunction = require('./_a-function');

function PromiseCapability(C) {
  var resolve, reject;
  this.promise = new C(function ($$resolve, $$reject) {
    if (resolve !== undefined || reject !== undefined) throw TypeError('Bad Promise constructor');
    resolve = $$resolve;
    reject = $$reject;
  });
  this.resolve = aFunction(resolve);
  this.reject = aFunction(reject);
}

module.exports.f = function (C) {
  return new PromiseCapability(C);
};

},{"./_a-function":26}],63:[function(require,module,exports){
// 19.1.2.2 / 15.2.3.5 Object.create(O [, Properties])
var anObject = require('./_an-object');
var dPs = require('./_object-dps');
var enumBugKeys = require('./_enum-bug-keys');
var IE_PROTO = require('./_shared-key')('IE_PROTO');
var Empty = function () { /* empty */ };
var PROTOTYPE = 'prototype';

// Create object with fake `null` prototype: use iframe Object with cleared prototype
var createDict = function () {
  // Thrash, waste and sodomy: IE GC bug
  var iframe = require('./_dom-create')('iframe');
  var i = enumBugKeys.length;
  var lt = '<';
  var gt = '>';
  var iframeDocument;
  iframe.style.display = 'none';
  require('./_html').appendChild(iframe);
  iframe.src = 'javascript:'; // eslint-disable-line no-script-url
  // createDict = iframe.contentWindow.Object;
  // html.removeChild(iframe);
  iframeDocument = iframe.contentWindow.document;
  iframeDocument.open();
  iframeDocument.write(lt + 'script' + gt + 'document.F=Object' + lt + '/script' + gt);
  iframeDocument.close();
  createDict = iframeDocument.F;
  while (i--) delete createDict[PROTOTYPE][enumBugKeys[i]];
  return createDict();
};

module.exports = Object.create || function create(O, Properties) {
  var result;
  if (O !== null) {
    Empty[PROTOTYPE] = anObject(O);
    result = new Empty();
    Empty[PROTOTYPE] = null;
    // add "__proto__" for Object.getPrototypeOf polyfill
    result[IE_PROTO] = O;
  } else result = createDict();
  return Properties === undefined ? result : dPs(result, Properties);
};

},{"./_an-object":29,"./_dom-create":37,"./_enum-bug-keys":38,"./_html":46,"./_object-dps":65,"./_shared-key":82}],64:[function(require,module,exports){
var anObject = require('./_an-object');
var IE8_DOM_DEFINE = require('./_ie8-dom-define');
var toPrimitive = require('./_to-primitive');
var dP = Object.defineProperty;

exports.f = require('./_descriptors') ? Object.defineProperty : function defineProperty(O, P, Attributes) {
  anObject(O);
  P = toPrimitive(P, true);
  anObject(Attributes);
  if (IE8_DOM_DEFINE) try {
    return dP(O, P, Attributes);
  } catch (e) { /* empty */ }
  if ('get' in Attributes || 'set' in Attributes) throw TypeError('Accessors not supported!');
  if ('value' in Attributes) O[P] = Attributes.value;
  return O;
};

},{"./_an-object":29,"./_descriptors":36,"./_ie8-dom-define":47,"./_to-primitive":92}],65:[function(require,module,exports){
var dP = require('./_object-dp');
var anObject = require('./_an-object');
var getKeys = require('./_object-keys');

module.exports = require('./_descriptors') ? Object.defineProperties : function defineProperties(O, Properties) {
  anObject(O);
  var keys = getKeys(Properties);
  var length = keys.length;
  var i = 0;
  var P;
  while (length > i) dP.f(O, P = keys[i++], Properties[P]);
  return O;
};

},{"./_an-object":29,"./_descriptors":36,"./_object-dp":64,"./_object-keys":72}],66:[function(require,module,exports){
var pIE = require('./_object-pie');
var createDesc = require('./_property-desc');
var toIObject = require('./_to-iobject');
var toPrimitive = require('./_to-primitive');
var has = require('./_has');
var IE8_DOM_DEFINE = require('./_ie8-dom-define');
var gOPD = Object.getOwnPropertyDescriptor;

exports.f = require('./_descriptors') ? gOPD : function getOwnPropertyDescriptor(O, P) {
  O = toIObject(O);
  P = toPrimitive(P, true);
  if (IE8_DOM_DEFINE) try {
    return gOPD(O, P);
  } catch (e) { /* empty */ }
  if (has(O, P)) return createDesc(!pIE.f.call(O, P), O[P]);
};

},{"./_descriptors":36,"./_has":44,"./_ie8-dom-define":47,"./_object-pie":73,"./_property-desc":76,"./_to-iobject":89,"./_to-primitive":92}],67:[function(require,module,exports){
// fallback for IE11 buggy Object.getOwnPropertyNames with iframe and window
var toIObject = require('./_to-iobject');
var gOPN = require('./_object-gopn').f;
var toString = {}.toString;

var windowNames = typeof window == 'object' && window && Object.getOwnPropertyNames
  ? Object.getOwnPropertyNames(window) : [];

var getWindowNames = function (it) {
  try {
    return gOPN(it);
  } catch (e) {
    return windowNames.slice();
  }
};

module.exports.f = function getOwnPropertyNames(it) {
  return windowNames && toString.call(it) == '[object Window]' ? getWindowNames(it) : gOPN(toIObject(it));
};

},{"./_object-gopn":68,"./_to-iobject":89}],68:[function(require,module,exports){
// 19.1.2.7 / 15.2.3.4 Object.getOwnPropertyNames(O)
var $keys = require('./_object-keys-internal');
var hiddenKeys = require('./_enum-bug-keys').concat('length', 'prototype');

exports.f = Object.getOwnPropertyNames || function getOwnPropertyNames(O) {
  return $keys(O, hiddenKeys);
};

},{"./_enum-bug-keys":38,"./_object-keys-internal":71}],69:[function(require,module,exports){
exports.f = Object.getOwnPropertySymbols;

},{}],70:[function(require,module,exports){
// 19.1.2.9 / 15.2.3.2 Object.getPrototypeOf(O)
var has = require('./_has');
var toObject = require('./_to-object');
var IE_PROTO = require('./_shared-key')('IE_PROTO');
var ObjectProto = Object.prototype;

module.exports = Object.getPrototypeOf || function (O) {
  O = toObject(O);
  if (has(O, IE_PROTO)) return O[IE_PROTO];
  if (typeof O.constructor == 'function' && O instanceof O.constructor) {
    return O.constructor.prototype;
  } return O instanceof Object ? ObjectProto : null;
};

},{"./_has":44,"./_shared-key":82,"./_to-object":91}],71:[function(require,module,exports){
var has = require('./_has');
var toIObject = require('./_to-iobject');
var arrayIndexOf = require('./_array-includes')(false);
var IE_PROTO = require('./_shared-key')('IE_PROTO');

module.exports = function (object, names) {
  var O = toIObject(object);
  var i = 0;
  var result = [];
  var key;
  for (key in O) if (key != IE_PROTO) has(O, key) && result.push(key);
  // Don't enum bug & hidden keys
  while (names.length > i) if (has(O, key = names[i++])) {
    ~arrayIndexOf(result, key) || result.push(key);
  }
  return result;
};

},{"./_array-includes":30,"./_has":44,"./_shared-key":82,"./_to-iobject":89}],72:[function(require,module,exports){
// 19.1.2.14 / 15.2.3.14 Object.keys(O)
var $keys = require('./_object-keys-internal');
var enumBugKeys = require('./_enum-bug-keys');

module.exports = Object.keys || function keys(O) {
  return $keys(O, enumBugKeys);
};

},{"./_enum-bug-keys":38,"./_object-keys-internal":71}],73:[function(require,module,exports){
exports.f = {}.propertyIsEnumerable;

},{}],74:[function(require,module,exports){
module.exports = function (exec) {
  try {
    return { e: false, v: exec() };
  } catch (e) {
    return { e: true, v: e };
  }
};

},{}],75:[function(require,module,exports){
var anObject = require('./_an-object');
var isObject = require('./_is-object');
var newPromiseCapability = require('./_new-promise-capability');

module.exports = function (C, x) {
  anObject(C);
  if (isObject(x) && x.constructor === C) return x;
  var promiseCapability = newPromiseCapability.f(C);
  var resolve = promiseCapability.resolve;
  resolve(x);
  return promiseCapability.promise;
};

},{"./_an-object":29,"./_is-object":52,"./_new-promise-capability":62}],76:[function(require,module,exports){
module.exports = function (bitmap, value) {
  return {
    enumerable: !(bitmap & 1),
    configurable: !(bitmap & 2),
    writable: !(bitmap & 4),
    value: value
  };
};

},{}],77:[function(require,module,exports){
var hide = require('./_hide');
module.exports = function (target, src, safe) {
  for (var key in src) {
    if (safe && target[key]) target[key] = src[key];
    else hide(target, key, src[key]);
  } return target;
};

},{"./_hide":45}],78:[function(require,module,exports){
module.exports = require('./_hide');

},{"./_hide":45}],79:[function(require,module,exports){
// Works with __proto__ only. Old v8 can't work with null proto objects.
/* eslint-disable no-proto */
var isObject = require('./_is-object');
var anObject = require('./_an-object');
var check = function (O, proto) {
  anObject(O);
  if (!isObject(proto) && proto !== null) throw TypeError(proto + ": can't set as prototype!");
};
module.exports = {
  set: Object.setPrototypeOf || ('__proto__' in {} ? // eslint-disable-line
    function (test, buggy, set) {
      try {
        set = require('./_ctx')(Function.call, require('./_object-gopd').f(Object.prototype, '__proto__').set, 2);
        set(test, []);
        buggy = !(test instanceof Array);
      } catch (e) { buggy = true; }
      return function setPrototypeOf(O, proto) {
        check(O, proto);
        if (buggy) O.__proto__ = proto;
        else set(O, proto);
        return O;
      };
    }({}, false) : undefined),
  check: check
};

},{"./_an-object":29,"./_ctx":34,"./_is-object":52,"./_object-gopd":66}],80:[function(require,module,exports){
'use strict';
var global = require('./_global');
var core = require('./_core');
var dP = require('./_object-dp');
var DESCRIPTORS = require('./_descriptors');
var SPECIES = require('./_wks')('species');

module.exports = function (KEY) {
  var C = typeof core[KEY] == 'function' ? core[KEY] : global[KEY];
  if (DESCRIPTORS && C && !C[SPECIES]) dP.f(C, SPECIES, {
    configurable: true,
    get: function () { return this; }
  });
};

},{"./_core":33,"./_descriptors":36,"./_global":43,"./_object-dp":64,"./_wks":97}],81:[function(require,module,exports){
var def = require('./_object-dp').f;
var has = require('./_has');
var TAG = require('./_wks')('toStringTag');

module.exports = function (it, tag, stat) {
  if (it && !has(it = stat ? it : it.prototype, TAG)) def(it, TAG, { configurable: true, value: tag });
};

},{"./_has":44,"./_object-dp":64,"./_wks":97}],82:[function(require,module,exports){
var shared = require('./_shared')('keys');
var uid = require('./_uid');
module.exports = function (key) {
  return shared[key] || (shared[key] = uid(key));
};

},{"./_shared":83,"./_uid":93}],83:[function(require,module,exports){
var core = require('./_core');
var global = require('./_global');
var SHARED = '__core-js_shared__';
var store = global[SHARED] || (global[SHARED] = {});

(module.exports = function (key, value) {
  return store[key] || (store[key] = value !== undefined ? value : {});
})('versions', []).push({
  version: core.version,
  mode: require('./_library') ? 'pure' : 'global',
  copyright: '© 2018 Denis Pushkarev (zloirock.ru)'
});

},{"./_core":33,"./_global":43,"./_library":59}],84:[function(require,module,exports){
// 7.3.20 SpeciesConstructor(O, defaultConstructor)
var anObject = require('./_an-object');
var aFunction = require('./_a-function');
var SPECIES = require('./_wks')('species');
module.exports = function (O, D) {
  var C = anObject(O).constructor;
  var S;
  return C === undefined || (S = anObject(C)[SPECIES]) == undefined ? D : aFunction(S);
};

},{"./_a-function":26,"./_an-object":29,"./_wks":97}],85:[function(require,module,exports){
var toInteger = require('./_to-integer');
var defined = require('./_defined');
// true  -> String#at
// false -> String#codePointAt
module.exports = function (TO_STRING) {
  return function (that, pos) {
    var s = String(defined(that));
    var i = toInteger(pos);
    var l = s.length;
    var a, b;
    if (i < 0 || i >= l) return TO_STRING ? '' : undefined;
    a = s.charCodeAt(i);
    return a < 0xd800 || a > 0xdbff || i + 1 === l || (b = s.charCodeAt(i + 1)) < 0xdc00 || b > 0xdfff
      ? TO_STRING ? s.charAt(i) : a
      : TO_STRING ? s.slice(i, i + 2) : (a - 0xd800 << 10) + (b - 0xdc00) + 0x10000;
  };
};

},{"./_defined":35,"./_to-integer":88}],86:[function(require,module,exports){
var ctx = require('./_ctx');
var invoke = require('./_invoke');
var html = require('./_html');
var cel = require('./_dom-create');
var global = require('./_global');
var process = global.process;
var setTask = global.setImmediate;
var clearTask = global.clearImmediate;
var MessageChannel = global.MessageChannel;
var Dispatch = global.Dispatch;
var counter = 0;
var queue = {};
var ONREADYSTATECHANGE = 'onreadystatechange';
var defer, channel, port;
var run = function () {
  var id = +this;
  // eslint-disable-next-line no-prototype-builtins
  if (queue.hasOwnProperty(id)) {
    var fn = queue[id];
    delete queue[id];
    fn();
  }
};
var listener = function (event) {
  run.call(event.data);
};
// Node.js 0.9+ & IE10+ has setImmediate, otherwise:
if (!setTask || !clearTask) {
  setTask = function setImmediate(fn) {
    var args = [];
    var i = 1;
    while (arguments.length > i) args.push(arguments[i++]);
    queue[++counter] = function () {
      // eslint-disable-next-line no-new-func
      invoke(typeof fn == 'function' ? fn : Function(fn), args);
    };
    defer(counter);
    return counter;
  };
  clearTask = function clearImmediate(id) {
    delete queue[id];
  };
  // Node.js 0.8-
  if (require('./_cof')(process) == 'process') {
    defer = function (id) {
      process.nextTick(ctx(run, id, 1));
    };
  // Sphere (JS game engine) Dispatch API
  } else if (Dispatch && Dispatch.now) {
    defer = function (id) {
      Dispatch.now(ctx(run, id, 1));
    };
  // Browsers with MessageChannel, includes WebWorkers
  } else if (MessageChannel) {
    channel = new MessageChannel();
    port = channel.port2;
    channel.port1.onmessage = listener;
    defer = ctx(port.postMessage, port, 1);
  // Browsers with postMessage, skip WebWorkers
  // IE8 has postMessage, but it's sync & typeof its postMessage is 'object'
  } else if (global.addEventListener && typeof postMessage == 'function' && !global.importScripts) {
    defer = function (id) {
      global.postMessage(id + '', '*');
    };
    global.addEventListener('message', listener, false);
  // IE8-
  } else if (ONREADYSTATECHANGE in cel('script')) {
    defer = function (id) {
      html.appendChild(cel('script'))[ONREADYSTATECHANGE] = function () {
        html.removeChild(this);
        run.call(id);
      };
    };
  // Rest old browsers
  } else {
    defer = function (id) {
      setTimeout(ctx(run, id, 1), 0);
    };
  }
}
module.exports = {
  set: setTask,
  clear: clearTask
};

},{"./_cof":32,"./_ctx":34,"./_dom-create":37,"./_global":43,"./_html":46,"./_invoke":48}],87:[function(require,module,exports){
var toInteger = require('./_to-integer');
var max = Math.max;
var min = Math.min;
module.exports = function (index, length) {
  index = toInteger(index);
  return index < 0 ? max(index + length, 0) : min(index, length);
};

},{"./_to-integer":88}],88:[function(require,module,exports){
// 7.1.4 ToInteger
var ceil = Math.ceil;
var floor = Math.floor;
module.exports = function (it) {
  return isNaN(it = +it) ? 0 : (it > 0 ? floor : ceil)(it);
};

},{}],89:[function(require,module,exports){
// to indexed object, toObject with fallback for non-array-like ES3 strings
var IObject = require('./_iobject');
var defined = require('./_defined');
module.exports = function (it) {
  return IObject(defined(it));
};

},{"./_defined":35,"./_iobject":49}],90:[function(require,module,exports){
// 7.1.15 ToLength
var toInteger = require('./_to-integer');
var min = Math.min;
module.exports = function (it) {
  return it > 0 ? min(toInteger(it), 0x1fffffffffffff) : 0; // pow(2, 53) - 1 == 9007199254740991
};

},{"./_to-integer":88}],91:[function(require,module,exports){
// 7.1.13 ToObject(argument)
var defined = require('./_defined');
module.exports = function (it) {
  return Object(defined(it));
};

},{"./_defined":35}],92:[function(require,module,exports){
// 7.1.1 ToPrimitive(input [, PreferredType])
var isObject = require('./_is-object');
// instead of the ES6 spec version, we didn't implement @@toPrimitive case
// and the second argument - flag - preferred type is a string
module.exports = function (it, S) {
  if (!isObject(it)) return it;
  var fn, val;
  if (S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  if (typeof (fn = it.valueOf) == 'function' && !isObject(val = fn.call(it))) return val;
  if (!S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  throw TypeError("Can't convert object to primitive value");
};

},{"./_is-object":52}],93:[function(require,module,exports){
var id = 0;
var px = Math.random();
module.exports = function (key) {
  return 'Symbol('.concat(key === undefined ? '' : key, ')_', (++id + px).toString(36));
};

},{}],94:[function(require,module,exports){
var global = require('./_global');
var navigator = global.navigator;

module.exports = navigator && navigator.userAgent || '';

},{"./_global":43}],95:[function(require,module,exports){
var global = require('./_global');
var core = require('./_core');
var LIBRARY = require('./_library');
var wksExt = require('./_wks-ext');
var defineProperty = require('./_object-dp').f;
module.exports = function (name) {
  var $Symbol = core.Symbol || (core.Symbol = LIBRARY ? {} : global.Symbol || {});
  if (name.charAt(0) != '_' && !(name in $Symbol)) defineProperty($Symbol, name, { value: wksExt.f(name) });
};

},{"./_core":33,"./_global":43,"./_library":59,"./_object-dp":64,"./_wks-ext":96}],96:[function(require,module,exports){
exports.f = require('./_wks');

},{"./_wks":97}],97:[function(require,module,exports){
var store = require('./_shared')('wks');
var uid = require('./_uid');
var Symbol = require('./_global').Symbol;
var USE_SYMBOL = typeof Symbol == 'function';

var $exports = module.exports = function (name) {
  return store[name] || (store[name] =
    USE_SYMBOL && Symbol[name] || (USE_SYMBOL ? Symbol : uid)('Symbol.' + name));
};

$exports.store = store;

},{"./_global":43,"./_shared":83,"./_uid":93}],98:[function(require,module,exports){
var classof = require('./_classof');
var ITERATOR = require('./_wks')('iterator');
var Iterators = require('./_iterators');
module.exports = require('./_core').getIteratorMethod = function (it) {
  if (it != undefined) return it[ITERATOR]
    || it['@@iterator']
    || Iterators[classof(it)];
};

},{"./_classof":31,"./_core":33,"./_iterators":58,"./_wks":97}],99:[function(require,module,exports){
'use strict';
var addToUnscopables = require('./_add-to-unscopables');
var step = require('./_iter-step');
var Iterators = require('./_iterators');
var toIObject = require('./_to-iobject');

// 22.1.3.4 Array.prototype.entries()
// 22.1.3.13 Array.prototype.keys()
// 22.1.3.29 Array.prototype.values()
// 22.1.3.30 Array.prototype[@@iterator]()
module.exports = require('./_iter-define')(Array, 'Array', function (iterated, kind) {
  this._t = toIObject(iterated); // target
  this._i = 0;                   // next index
  this._k = kind;                // kind
// 22.1.5.2.1 %ArrayIteratorPrototype%.next()
}, function () {
  var O = this._t;
  var kind = this._k;
  var index = this._i++;
  if (!O || index >= O.length) {
    this._t = undefined;
    return step(1);
  }
  if (kind == 'keys') return step(0, index);
  if (kind == 'values') return step(0, O[index]);
  return step(0, [index, O[index]]);
}, 'values');

// argumentsList[@@iterator] is %ArrayProto_values% (9.4.4.6, 9.4.4.7)
Iterators.Arguments = Iterators.Array;

addToUnscopables('keys');
addToUnscopables('values');
addToUnscopables('entries');

},{"./_add-to-unscopables":27,"./_iter-define":55,"./_iter-step":57,"./_iterators":58,"./_to-iobject":89}],100:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.2 / 15.2.3.5 Object.create(O [, Properties])
$export($export.S, 'Object', { create: require('./_object-create') });

},{"./_export":40,"./_object-create":63}],101:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.4 / 15.2.3.6 Object.defineProperty(O, P, Attributes)
$export($export.S + $export.F * !require('./_descriptors'), 'Object', { defineProperty: require('./_object-dp').f });

},{"./_descriptors":36,"./_export":40,"./_object-dp":64}],102:[function(require,module,exports){
// 19.1.3.19 Object.setPrototypeOf(O, proto)
var $export = require('./_export');
$export($export.S, 'Object', { setPrototypeOf: require('./_set-proto').set });

},{"./_export":40,"./_set-proto":79}],103:[function(require,module,exports){

},{}],104:[function(require,module,exports){
'use strict';
var LIBRARY = require('./_library');
var global = require('./_global');
var ctx = require('./_ctx');
var classof = require('./_classof');
var $export = require('./_export');
var isObject = require('./_is-object');
var aFunction = require('./_a-function');
var anInstance = require('./_an-instance');
var forOf = require('./_for-of');
var speciesConstructor = require('./_species-constructor');
var task = require('./_task').set;
var microtask = require('./_microtask')();
var newPromiseCapabilityModule = require('./_new-promise-capability');
var perform = require('./_perform');
var userAgent = require('./_user-agent');
var promiseResolve = require('./_promise-resolve');
var PROMISE = 'Promise';
var TypeError = global.TypeError;
var process = global.process;
var versions = process && process.versions;
var v8 = versions && versions.v8 || '';
var $Promise = global[PROMISE];
var isNode = classof(process) == 'process';
var empty = function () { /* empty */ };
var Internal, newGenericPromiseCapability, OwnPromiseCapability, Wrapper;
var newPromiseCapability = newGenericPromiseCapability = newPromiseCapabilityModule.f;

var USE_NATIVE = !!function () {
  try {
    // correct subclassing with @@species support
    var promise = $Promise.resolve(1);
    var FakePromise = (promise.constructor = {})[require('./_wks')('species')] = function (exec) {
      exec(empty, empty);
    };
    // unhandled rejections tracking support, NodeJS Promise without it fails @@species test
    return (isNode || typeof PromiseRejectionEvent == 'function')
      && promise.then(empty) instanceof FakePromise
      // v8 6.6 (Node 10 and Chrome 66) have a bug with resolving custom thenables
      // https://bugs.chromium.org/p/chromium/issues/detail?id=830565
      // we can't detect it synchronously, so just check versions
      && v8.indexOf('6.6') !== 0
      && userAgent.indexOf('Chrome/66') === -1;
  } catch (e) { /* empty */ }
}();

// helpers
var isThenable = function (it) {
  var then;
  return isObject(it) && typeof (then = it.then) == 'function' ? then : false;
};
var notify = function (promise, isReject) {
  if (promise._n) return;
  promise._n = true;
  var chain = promise._c;
  microtask(function () {
    var value = promise._v;
    var ok = promise._s == 1;
    var i = 0;
    var run = function (reaction) {
      var handler = ok ? reaction.ok : reaction.fail;
      var resolve = reaction.resolve;
      var reject = reaction.reject;
      var domain = reaction.domain;
      var result, then, exited;
      try {
        if (handler) {
          if (!ok) {
            if (promise._h == 2) onHandleUnhandled(promise);
            promise._h = 1;
          }
          if (handler === true) result = value;
          else {
            if (domain) domain.enter();
            result = handler(value); // may throw
            if (domain) {
              domain.exit();
              exited = true;
            }
          }
          if (result === reaction.promise) {
            reject(TypeError('Promise-chain cycle'));
          } else if (then = isThenable(result)) {
            then.call(result, resolve, reject);
          } else resolve(result);
        } else reject(value);
      } catch (e) {
        if (domain && !exited) domain.exit();
        reject(e);
      }
    };
    while (chain.length > i) run(chain[i++]); // variable length - can't use forEach
    promise._c = [];
    promise._n = false;
    if (isReject && !promise._h) onUnhandled(promise);
  });
};
var onUnhandled = function (promise) {
  task.call(global, function () {
    var value = promise._v;
    var unhandled = isUnhandled(promise);
    var result, handler, console;
    if (unhandled) {
      result = perform(function () {
        if (isNode) {
          process.emit('unhandledRejection', value, promise);
        } else if (handler = global.onunhandledrejection) {
          handler({ promise: promise, reason: value });
        } else if ((console = global.console) && console.error) {
          console.error('Unhandled promise rejection', value);
        }
      });
      // Browsers should not trigger `rejectionHandled` event if it was handled here, NodeJS - should
      promise._h = isNode || isUnhandled(promise) ? 2 : 1;
    } promise._a = undefined;
    if (unhandled && result.e) throw result.v;
  });
};
var isUnhandled = function (promise) {
  return promise._h !== 1 && (promise._a || promise._c).length === 0;
};
var onHandleUnhandled = function (promise) {
  task.call(global, function () {
    var handler;
    if (isNode) {
      process.emit('rejectionHandled', promise);
    } else if (handler = global.onrejectionhandled) {
      handler({ promise: promise, reason: promise._v });
    }
  });
};
var $reject = function (value) {
  var promise = this;
  if (promise._d) return;
  promise._d = true;
  promise = promise._w || promise; // unwrap
  promise._v = value;
  promise._s = 2;
  if (!promise._a) promise._a = promise._c.slice();
  notify(promise, true);
};
var $resolve = function (value) {
  var promise = this;
  var then;
  if (promise._d) return;
  promise._d = true;
  promise = promise._w || promise; // unwrap
  try {
    if (promise === value) throw TypeError("Promise can't be resolved itself");
    if (then = isThenable(value)) {
      microtask(function () {
        var wrapper = { _w: promise, _d: false }; // wrap
        try {
          then.call(value, ctx($resolve, wrapper, 1), ctx($reject, wrapper, 1));
        } catch (e) {
          $reject.call(wrapper, e);
        }
      });
    } else {
      promise._v = value;
      promise._s = 1;
      notify(promise, false);
    }
  } catch (e) {
    $reject.call({ _w: promise, _d: false }, e); // wrap
  }
};

// constructor polyfill
if (!USE_NATIVE) {
  // 25.4.3.1 Promise(executor)
  $Promise = function Promise(executor) {
    anInstance(this, $Promise, PROMISE, '_h');
    aFunction(executor);
    Internal.call(this);
    try {
      executor(ctx($resolve, this, 1), ctx($reject, this, 1));
    } catch (err) {
      $reject.call(this, err);
    }
  };
  // eslint-disable-next-line no-unused-vars
  Internal = function Promise(executor) {
    this._c = [];             // <- awaiting reactions
    this._a = undefined;      // <- checked in isUnhandled reactions
    this._s = 0;              // <- state
    this._d = false;          // <- done
    this._v = undefined;      // <- value
    this._h = 0;              // <- rejection state, 0 - default, 1 - handled, 2 - unhandled
    this._n = false;          // <- notify
  };
  Internal.prototype = require('./_redefine-all')($Promise.prototype, {
    // 25.4.5.3 Promise.prototype.then(onFulfilled, onRejected)
    then: function then(onFulfilled, onRejected) {
      var reaction = newPromiseCapability(speciesConstructor(this, $Promise));
      reaction.ok = typeof onFulfilled == 'function' ? onFulfilled : true;
      reaction.fail = typeof onRejected == 'function' && onRejected;
      reaction.domain = isNode ? process.domain : undefined;
      this._c.push(reaction);
      if (this._a) this._a.push(reaction);
      if (this._s) notify(this, false);
      return reaction.promise;
    },
    // 25.4.5.1 Promise.prototype.catch(onRejected)
    'catch': function (onRejected) {
      return this.then(undefined, onRejected);
    }
  });
  OwnPromiseCapability = function () {
    var promise = new Internal();
    this.promise = promise;
    this.resolve = ctx($resolve, promise, 1);
    this.reject = ctx($reject, promise, 1);
  };
  newPromiseCapabilityModule.f = newPromiseCapability = function (C) {
    return C === $Promise || C === Wrapper
      ? new OwnPromiseCapability(C)
      : newGenericPromiseCapability(C);
  };
}

$export($export.G + $export.W + $export.F * !USE_NATIVE, { Promise: $Promise });
require('./_set-to-string-tag')($Promise, PROMISE);
require('./_set-species')(PROMISE);
Wrapper = require('./_core')[PROMISE];

// statics
$export($export.S + $export.F * !USE_NATIVE, PROMISE, {
  // 25.4.4.5 Promise.reject(r)
  reject: function reject(r) {
    var capability = newPromiseCapability(this);
    var $$reject = capability.reject;
    $$reject(r);
    return capability.promise;
  }
});
$export($export.S + $export.F * (LIBRARY || !USE_NATIVE), PROMISE, {
  // 25.4.4.6 Promise.resolve(x)
  resolve: function resolve(x) {
    return promiseResolve(LIBRARY && this === Wrapper ? $Promise : this, x);
  }
});
$export($export.S + $export.F * !(USE_NATIVE && require('./_iter-detect')(function (iter) {
  $Promise.all(iter)['catch'](empty);
})), PROMISE, {
  // 25.4.4.1 Promise.all(iterable)
  all: function all(iterable) {
    var C = this;
    var capability = newPromiseCapability(C);
    var resolve = capability.resolve;
    var reject = capability.reject;
    var result = perform(function () {
      var values = [];
      var index = 0;
      var remaining = 1;
      forOf(iterable, false, function (promise) {
        var $index = index++;
        var alreadyCalled = false;
        values.push(undefined);
        remaining++;
        C.resolve(promise).then(function (value) {
          if (alreadyCalled) return;
          alreadyCalled = true;
          values[$index] = value;
          --remaining || resolve(values);
        }, reject);
      });
      --remaining || resolve(values);
    });
    if (result.e) reject(result.v);
    return capability.promise;
  },
  // 25.4.4.4 Promise.race(iterable)
  race: function race(iterable) {
    var C = this;
    var capability = newPromiseCapability(C);
    var reject = capability.reject;
    var result = perform(function () {
      forOf(iterable, false, function (promise) {
        C.resolve(promise).then(capability.resolve, reject);
      });
    });
    if (result.e) reject(result.v);
    return capability.promise;
  }
});

},{"./_a-function":26,"./_an-instance":28,"./_classof":31,"./_core":33,"./_ctx":34,"./_export":40,"./_for-of":42,"./_global":43,"./_is-object":52,"./_iter-detect":56,"./_library":59,"./_microtask":61,"./_new-promise-capability":62,"./_perform":74,"./_promise-resolve":75,"./_redefine-all":77,"./_set-species":80,"./_set-to-string-tag":81,"./_species-constructor":84,"./_task":86,"./_user-agent":94,"./_wks":97}],105:[function(require,module,exports){
'use strict';
var $at = require('./_string-at')(true);

// 21.1.3.27 String.prototype[@@iterator]()
require('./_iter-define')(String, 'String', function (iterated) {
  this._t = String(iterated); // target
  this._i = 0;                // next index
// 21.1.5.2.1 %StringIteratorPrototype%.next()
}, function () {
  var O = this._t;
  var index = this._i;
  var point;
  if (index >= O.length) return { value: undefined, done: true };
  point = $at(O, index);
  this._i += point.length;
  return { value: point, done: false };
});

},{"./_iter-define":55,"./_string-at":85}],106:[function(require,module,exports){
'use strict';
// ECMAScript 6 symbols shim
var global = require('./_global');
var has = require('./_has');
var DESCRIPTORS = require('./_descriptors');
var $export = require('./_export');
var redefine = require('./_redefine');
var META = require('./_meta').KEY;
var $fails = require('./_fails');
var shared = require('./_shared');
var setToStringTag = require('./_set-to-string-tag');
var uid = require('./_uid');
var wks = require('./_wks');
var wksExt = require('./_wks-ext');
var wksDefine = require('./_wks-define');
var enumKeys = require('./_enum-keys');
var isArray = require('./_is-array');
var anObject = require('./_an-object');
var isObject = require('./_is-object');
var toIObject = require('./_to-iobject');
var toPrimitive = require('./_to-primitive');
var createDesc = require('./_property-desc');
var _create = require('./_object-create');
var gOPNExt = require('./_object-gopn-ext');
var $GOPD = require('./_object-gopd');
var $DP = require('./_object-dp');
var $keys = require('./_object-keys');
var gOPD = $GOPD.f;
var dP = $DP.f;
var gOPN = gOPNExt.f;
var $Symbol = global.Symbol;
var $JSON = global.JSON;
var _stringify = $JSON && $JSON.stringify;
var PROTOTYPE = 'prototype';
var HIDDEN = wks('_hidden');
var TO_PRIMITIVE = wks('toPrimitive');
var isEnum = {}.propertyIsEnumerable;
var SymbolRegistry = shared('symbol-registry');
var AllSymbols = shared('symbols');
var OPSymbols = shared('op-symbols');
var ObjectProto = Object[PROTOTYPE];
var USE_NATIVE = typeof $Symbol == 'function';
var QObject = global.QObject;
// Don't use setters in Qt Script, https://github.com/zloirock/core-js/issues/173
var setter = !QObject || !QObject[PROTOTYPE] || !QObject[PROTOTYPE].findChild;

// fallback for old Android, https://code.google.com/p/v8/issues/detail?id=687
var setSymbolDesc = DESCRIPTORS && $fails(function () {
  return _create(dP({}, 'a', {
    get: function () { return dP(this, 'a', { value: 7 }).a; }
  })).a != 7;
}) ? function (it, key, D) {
  var protoDesc = gOPD(ObjectProto, key);
  if (protoDesc) delete ObjectProto[key];
  dP(it, key, D);
  if (protoDesc && it !== ObjectProto) dP(ObjectProto, key, protoDesc);
} : dP;

var wrap = function (tag) {
  var sym = AllSymbols[tag] = _create($Symbol[PROTOTYPE]);
  sym._k = tag;
  return sym;
};

var isSymbol = USE_NATIVE && typeof $Symbol.iterator == 'symbol' ? function (it) {
  return typeof it == 'symbol';
} : function (it) {
  return it instanceof $Symbol;
};

var $defineProperty = function defineProperty(it, key, D) {
  if (it === ObjectProto) $defineProperty(OPSymbols, key, D);
  anObject(it);
  key = toPrimitive(key, true);
  anObject(D);
  if (has(AllSymbols, key)) {
    if (!D.enumerable) {
      if (!has(it, HIDDEN)) dP(it, HIDDEN, createDesc(1, {}));
      it[HIDDEN][key] = true;
    } else {
      if (has(it, HIDDEN) && it[HIDDEN][key]) it[HIDDEN][key] = false;
      D = _create(D, { enumerable: createDesc(0, false) });
    } return setSymbolDesc(it, key, D);
  } return dP(it, key, D);
};
var $defineProperties = function defineProperties(it, P) {
  anObject(it);
  var keys = enumKeys(P = toIObject(P));
  var i = 0;
  var l = keys.length;
  var key;
  while (l > i) $defineProperty(it, key = keys[i++], P[key]);
  return it;
};
var $create = function create(it, P) {
  return P === undefined ? _create(it) : $defineProperties(_create(it), P);
};
var $propertyIsEnumerable = function propertyIsEnumerable(key) {
  var E = isEnum.call(this, key = toPrimitive(key, true));
  if (this === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key)) return false;
  return E || !has(this, key) || !has(AllSymbols, key) || has(this, HIDDEN) && this[HIDDEN][key] ? E : true;
};
var $getOwnPropertyDescriptor = function getOwnPropertyDescriptor(it, key) {
  it = toIObject(it);
  key = toPrimitive(key, true);
  if (it === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key)) return;
  var D = gOPD(it, key);
  if (D && has(AllSymbols, key) && !(has(it, HIDDEN) && it[HIDDEN][key])) D.enumerable = true;
  return D;
};
var $getOwnPropertyNames = function getOwnPropertyNames(it) {
  var names = gOPN(toIObject(it));
  var result = [];
  var i = 0;
  var key;
  while (names.length > i) {
    if (!has(AllSymbols, key = names[i++]) && key != HIDDEN && key != META) result.push(key);
  } return result;
};
var $getOwnPropertySymbols = function getOwnPropertySymbols(it) {
  var IS_OP = it === ObjectProto;
  var names = gOPN(IS_OP ? OPSymbols : toIObject(it));
  var result = [];
  var i = 0;
  var key;
  while (names.length > i) {
    if (has(AllSymbols, key = names[i++]) && (IS_OP ? has(ObjectProto, key) : true)) result.push(AllSymbols[key]);
  } return result;
};

// 19.4.1.1 Symbol([description])
if (!USE_NATIVE) {
  $Symbol = function Symbol() {
    if (this instanceof $Symbol) throw TypeError('Symbol is not a constructor!');
    var tag = uid(arguments.length > 0 ? arguments[0] : undefined);
    var $set = function (value) {
      if (this === ObjectProto) $set.call(OPSymbols, value);
      if (has(this, HIDDEN) && has(this[HIDDEN], tag)) this[HIDDEN][tag] = false;
      setSymbolDesc(this, tag, createDesc(1, value));
    };
    if (DESCRIPTORS && setter) setSymbolDesc(ObjectProto, tag, { configurable: true, set: $set });
    return wrap(tag);
  };
  redefine($Symbol[PROTOTYPE], 'toString', function toString() {
    return this._k;
  });

  $GOPD.f = $getOwnPropertyDescriptor;
  $DP.f = $defineProperty;
  require('./_object-gopn').f = gOPNExt.f = $getOwnPropertyNames;
  require('./_object-pie').f = $propertyIsEnumerable;
  require('./_object-gops').f = $getOwnPropertySymbols;

  if (DESCRIPTORS && !require('./_library')) {
    redefine(ObjectProto, 'propertyIsEnumerable', $propertyIsEnumerable, true);
  }

  wksExt.f = function (name) {
    return wrap(wks(name));
  };
}

$export($export.G + $export.W + $export.F * !USE_NATIVE, { Symbol: $Symbol });

for (var es6Symbols = (
  // 19.4.2.2, 19.4.2.3, 19.4.2.4, 19.4.2.6, 19.4.2.8, 19.4.2.9, 19.4.2.10, 19.4.2.11, 19.4.2.12, 19.4.2.13, 19.4.2.14
  'hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables'
).split(','), j = 0; es6Symbols.length > j;)wks(es6Symbols[j++]);

for (var wellKnownSymbols = $keys(wks.store), k = 0; wellKnownSymbols.length > k;) wksDefine(wellKnownSymbols[k++]);

$export($export.S + $export.F * !USE_NATIVE, 'Symbol', {
  // 19.4.2.1 Symbol.for(key)
  'for': function (key) {
    return has(SymbolRegistry, key += '')
      ? SymbolRegistry[key]
      : SymbolRegistry[key] = $Symbol(key);
  },
  // 19.4.2.5 Symbol.keyFor(sym)
  keyFor: function keyFor(sym) {
    if (!isSymbol(sym)) throw TypeError(sym + ' is not a symbol!');
    for (var key in SymbolRegistry) if (SymbolRegistry[key] === sym) return key;
  },
  useSetter: function () { setter = true; },
  useSimple: function () { setter = false; }
});

$export($export.S + $export.F * !USE_NATIVE, 'Object', {
  // 19.1.2.2 Object.create(O [, Properties])
  create: $create,
  // 19.1.2.4 Object.defineProperty(O, P, Attributes)
  defineProperty: $defineProperty,
  // 19.1.2.3 Object.defineProperties(O, Properties)
  defineProperties: $defineProperties,
  // 19.1.2.6 Object.getOwnPropertyDescriptor(O, P)
  getOwnPropertyDescriptor: $getOwnPropertyDescriptor,
  // 19.1.2.7 Object.getOwnPropertyNames(O)
  getOwnPropertyNames: $getOwnPropertyNames,
  // 19.1.2.8 Object.getOwnPropertySymbols(O)
  getOwnPropertySymbols: $getOwnPropertySymbols
});

// 24.3.2 JSON.stringify(value [, replacer [, space]])
$JSON && $export($export.S + $export.F * (!USE_NATIVE || $fails(function () {
  var S = $Symbol();
  // MS Edge converts symbol values to JSON as {}
  // WebKit converts symbol values to JSON as null
  // V8 throws on boxed symbols
  return _stringify([S]) != '[null]' || _stringify({ a: S }) != '{}' || _stringify(Object(S)) != '{}';
})), 'JSON', {
  stringify: function stringify(it) {
    var args = [it];
    var i = 1;
    var replacer, $replacer;
    while (arguments.length > i) args.push(arguments[i++]);
    $replacer = replacer = args[1];
    if (!isObject(replacer) && it === undefined || isSymbol(it)) return; // IE8 returns string on undefined
    if (!isArray(replacer)) replacer = function (key, value) {
      if (typeof $replacer == 'function') value = $replacer.call(this, key, value);
      if (!isSymbol(value)) return value;
    };
    args[1] = replacer;
    return _stringify.apply($JSON, args);
  }
});

// 19.4.3.4 Symbol.prototype[@@toPrimitive](hint)
$Symbol[PROTOTYPE][TO_PRIMITIVE] || require('./_hide')($Symbol[PROTOTYPE], TO_PRIMITIVE, $Symbol[PROTOTYPE].valueOf);
// 19.4.3.5 Symbol.prototype[@@toStringTag]
setToStringTag($Symbol, 'Symbol');
// 20.2.1.9 Math[@@toStringTag]
setToStringTag(Math, 'Math', true);
// 24.3.3 JSON[@@toStringTag]
setToStringTag(global.JSON, 'JSON', true);

},{"./_an-object":29,"./_descriptors":36,"./_enum-keys":39,"./_export":40,"./_fails":41,"./_global":43,"./_has":44,"./_hide":45,"./_is-array":51,"./_is-object":52,"./_library":59,"./_meta":60,"./_object-create":63,"./_object-dp":64,"./_object-gopd":66,"./_object-gopn":68,"./_object-gopn-ext":67,"./_object-gops":69,"./_object-keys":72,"./_object-pie":73,"./_property-desc":76,"./_redefine":78,"./_set-to-string-tag":81,"./_shared":83,"./_to-iobject":89,"./_to-primitive":92,"./_uid":93,"./_wks":97,"./_wks-define":95,"./_wks-ext":96}],107:[function(require,module,exports){
// https://github.com/tc39/proposal-promise-finally
'use strict';
var $export = require('./_export');
var core = require('./_core');
var global = require('./_global');
var speciesConstructor = require('./_species-constructor');
var promiseResolve = require('./_promise-resolve');

$export($export.P + $export.R, 'Promise', { 'finally': function (onFinally) {
  var C = speciesConstructor(this, core.Promise || global.Promise);
  var isFunction = typeof onFinally == 'function';
  return this.then(
    isFunction ? function (x) {
      return promiseResolve(C, onFinally()).then(function () { return x; });
    } : onFinally,
    isFunction ? function (e) {
      return promiseResolve(C, onFinally()).then(function () { throw e; });
    } : onFinally
  );
} });

},{"./_core":33,"./_export":40,"./_global":43,"./_promise-resolve":75,"./_species-constructor":84}],108:[function(require,module,exports){
'use strict';
// https://github.com/tc39/proposal-promise-try
var $export = require('./_export');
var newPromiseCapability = require('./_new-promise-capability');
var perform = require('./_perform');

$export($export.S, 'Promise', { 'try': function (callbackfn) {
  var promiseCapability = newPromiseCapability.f(this);
  var result = perform(callbackfn);
  (result.e ? promiseCapability.reject : promiseCapability.resolve)(result.v);
  return promiseCapability.promise;
} });

},{"./_export":40,"./_new-promise-capability":62,"./_perform":74}],109:[function(require,module,exports){
require('./_wks-define')('asyncIterator');

},{"./_wks-define":95}],110:[function(require,module,exports){
require('./_wks-define')('observable');

},{"./_wks-define":95}],111:[function(require,module,exports){
require('./es6.array.iterator');
var global = require('./_global');
var hide = require('./_hide');
var Iterators = require('./_iterators');
var TO_STRING_TAG = require('./_wks')('toStringTag');

var DOMIterables = ('CSSRuleList,CSSStyleDeclaration,CSSValueList,ClientRectList,DOMRectList,DOMStringList,' +
  'DOMTokenList,DataTransferItemList,FileList,HTMLAllCollection,HTMLCollection,HTMLFormElement,HTMLSelectElement,' +
  'MediaList,MimeTypeArray,NamedNodeMap,NodeList,PaintRequestList,Plugin,PluginArray,SVGLengthList,SVGNumberList,' +
  'SVGPathSegList,SVGPointList,SVGStringList,SVGTransformList,SourceBufferList,StyleSheetList,TextTrackCueList,' +
  'TextTrackList,TouchList').split(',');

for (var i = 0; i < DOMIterables.length; i++) {
  var NAME = DOMIterables[i];
  var Collection = global[NAME];
  var proto = Collection && Collection.prototype;
  if (proto && !proto[TO_STRING_TAG]) hide(proto, TO_STRING_TAG, NAME);
  Iterators[NAME] = Iterators.Array;
}

},{"./_global":43,"./_hide":45,"./_iterators":58,"./_wks":97,"./es6.array.iterator":99}],112:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var objectCreate = Object.create || objectCreatePolyfill
var objectKeys = Object.keys || objectKeysPolyfill
var bind = Function.prototype.bind || functionBindPolyfill

function EventEmitter() {
  if (!this._events || !Object.prototype.hasOwnProperty.call(this, '_events')) {
    this._events = objectCreate(null);
    this._eventsCount = 0;
  }

  this._maxListeners = this._maxListeners || undefined;
}
module.exports = EventEmitter;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
var defaultMaxListeners = 10;

var hasDefineProperty;
try {
  var o = {};
  if (Object.defineProperty) Object.defineProperty(o, 'x', { value: 0 });
  hasDefineProperty = o.x === 0;
} catch (err) { hasDefineProperty = false }
if (hasDefineProperty) {
  Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
    enumerable: true,
    get: function() {
      return defaultMaxListeners;
    },
    set: function(arg) {
      // check whether the input is a positive number (whose value is zero or
      // greater and not a NaN).
      if (typeof arg !== 'number' || arg < 0 || arg !== arg)
        throw new TypeError('"defaultMaxListeners" must be a positive number');
      defaultMaxListeners = arg;
    }
  });
} else {
  EventEmitter.defaultMaxListeners = defaultMaxListeners;
}

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || isNaN(n))
    throw new TypeError('"n" argument must be a positive number');
  this._maxListeners = n;
  return this;
};

function $getMaxListeners(that) {
  if (that._maxListeners === undefined)
    return EventEmitter.defaultMaxListeners;
  return that._maxListeners;
}

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  return $getMaxListeners(this);
};

// These standalone emit* functions are used to optimize calling of event
// handlers for fast cases because emit() itself often has a variable number of
// arguments and can be deoptimized because of that. These functions always have
// the same number of arguments and thus do not get deoptimized, so the code
// inside them can execute faster.
function emitNone(handler, isFn, self) {
  if (isFn)
    handler.call(self);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].call(self);
  }
}
function emitOne(handler, isFn, self, arg1) {
  if (isFn)
    handler.call(self, arg1);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].call(self, arg1);
  }
}
function emitTwo(handler, isFn, self, arg1, arg2) {
  if (isFn)
    handler.call(self, arg1, arg2);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].call(self, arg1, arg2);
  }
}
function emitThree(handler, isFn, self, arg1, arg2, arg3) {
  if (isFn)
    handler.call(self, arg1, arg2, arg3);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].call(self, arg1, arg2, arg3);
  }
}

function emitMany(handler, isFn, self, args) {
  if (isFn)
    handler.apply(self, args);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].apply(self, args);
  }
}

EventEmitter.prototype.emit = function emit(type) {
  var er, handler, len, args, i, events;
  var doError = (type === 'error');

  events = this._events;
  if (events)
    doError = (doError && events.error == null);
  else if (!doError)
    return false;

  // If there is no 'error' event listener then throw.
  if (doError) {
    if (arguments.length > 1)
      er = arguments[1];
    if (er instanceof Error) {
      throw er; // Unhandled 'error' event
    } else {
      // At least give some kind of context to the user
      var err = new Error('Unhandled "error" event. (' + er + ')');
      err.context = er;
      throw err;
    }
    return false;
  }

  handler = events[type];

  if (!handler)
    return false;

  var isFn = typeof handler === 'function';
  len = arguments.length;
  switch (len) {
      // fast cases
    case 1:
      emitNone(handler, isFn, this);
      break;
    case 2:
      emitOne(handler, isFn, this, arguments[1]);
      break;
    case 3:
      emitTwo(handler, isFn, this, arguments[1], arguments[2]);
      break;
    case 4:
      emitThree(handler, isFn, this, arguments[1], arguments[2], arguments[3]);
      break;
      // slower
    default:
      args = new Array(len - 1);
      for (i = 1; i < len; i++)
        args[i - 1] = arguments[i];
      emitMany(handler, isFn, this, args);
  }

  return true;
};

function _addListener(target, type, listener, prepend) {
  var m;
  var events;
  var existing;

  if (typeof listener !== 'function')
    throw new TypeError('"listener" argument must be a function');

  events = target._events;
  if (!events) {
    events = target._events = objectCreate(null);
    target._eventsCount = 0;
  } else {
    // To avoid recursion in the case that type === "newListener"! Before
    // adding it to the listeners, first emit "newListener".
    if (events.newListener) {
      target.emit('newListener', type,
          listener.listener ? listener.listener : listener);

      // Re-assign `events` because a newListener handler could have caused the
      // this._events to be assigned to a new object
      events = target._events;
    }
    existing = events[type];
  }

  if (!existing) {
    // Optimize the case of one listener. Don't need the extra array object.
    existing = events[type] = listener;
    ++target._eventsCount;
  } else {
    if (typeof existing === 'function') {
      // Adding the second element, need to change to array.
      existing = events[type] =
          prepend ? [listener, existing] : [existing, listener];
    } else {
      // If we've already got an array, just append.
      if (prepend) {
        existing.unshift(listener);
      } else {
        existing.push(listener);
      }
    }

    // Check for listener leak
    if (!existing.warned) {
      m = $getMaxListeners(target);
      if (m && m > 0 && existing.length > m) {
        existing.warned = true;
        var w = new Error('Possible EventEmitter memory leak detected. ' +
            existing.length + ' "' + String(type) + '" listeners ' +
            'added. Use emitter.setMaxListeners() to ' +
            'increase limit.');
        w.name = 'MaxListenersExceededWarning';
        w.emitter = target;
        w.type = type;
        w.count = existing.length;
        if (typeof console === 'object' && console.warn) {
          console.warn('%s: %s', w.name, w.message);
        }
      }
    }
  }

  return target;
}

EventEmitter.prototype.addListener = function addListener(type, listener) {
  return _addListener(this, type, listener, false);
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.prependListener =
    function prependListener(type, listener) {
      return _addListener(this, type, listener, true);
    };

function onceWrapper() {
  if (!this.fired) {
    this.target.removeListener(this.type, this.wrapFn);
    this.fired = true;
    switch (arguments.length) {
      case 0:
        return this.listener.call(this.target);
      case 1:
        return this.listener.call(this.target, arguments[0]);
      case 2:
        return this.listener.call(this.target, arguments[0], arguments[1]);
      case 3:
        return this.listener.call(this.target, arguments[0], arguments[1],
            arguments[2]);
      default:
        var args = new Array(arguments.length);
        for (var i = 0; i < args.length; ++i)
          args[i] = arguments[i];
        this.listener.apply(this.target, args);
    }
  }
}

function _onceWrap(target, type, listener) {
  var state = { fired: false, wrapFn: undefined, target: target, type: type, listener: listener };
  var wrapped = bind.call(onceWrapper, state);
  wrapped.listener = listener;
  state.wrapFn = wrapped;
  return wrapped;
}

EventEmitter.prototype.once = function once(type, listener) {
  if (typeof listener !== 'function')
    throw new TypeError('"listener" argument must be a function');
  this.on(type, _onceWrap(this, type, listener));
  return this;
};

EventEmitter.prototype.prependOnceListener =
    function prependOnceListener(type, listener) {
      if (typeof listener !== 'function')
        throw new TypeError('"listener" argument must be a function');
      this.prependListener(type, _onceWrap(this, type, listener));
      return this;
    };

// Emits a 'removeListener' event if and only if the listener was removed.
EventEmitter.prototype.removeListener =
    function removeListener(type, listener) {
      var list, events, position, i, originalListener;

      if (typeof listener !== 'function')
        throw new TypeError('"listener" argument must be a function');

      events = this._events;
      if (!events)
        return this;

      list = events[type];
      if (!list)
        return this;

      if (list === listener || list.listener === listener) {
        if (--this._eventsCount === 0)
          this._events = objectCreate(null);
        else {
          delete events[type];
          if (events.removeListener)
            this.emit('removeListener', type, list.listener || listener);
        }
      } else if (typeof list !== 'function') {
        position = -1;

        for (i = list.length - 1; i >= 0; i--) {
          if (list[i] === listener || list[i].listener === listener) {
            originalListener = list[i].listener;
            position = i;
            break;
          }
        }

        if (position < 0)
          return this;

        if (position === 0)
          list.shift();
        else
          spliceOne(list, position);

        if (list.length === 1)
          events[type] = list[0];

        if (events.removeListener)
          this.emit('removeListener', type, originalListener || listener);
      }

      return this;
    };

EventEmitter.prototype.removeAllListeners =
    function removeAllListeners(type) {
      var listeners, events, i;

      events = this._events;
      if (!events)
        return this;

      // not listening for removeListener, no need to emit
      if (!events.removeListener) {
        if (arguments.length === 0) {
          this._events = objectCreate(null);
          this._eventsCount = 0;
        } else if (events[type]) {
          if (--this._eventsCount === 0)
            this._events = objectCreate(null);
          else
            delete events[type];
        }
        return this;
      }

      // emit removeListener for all listeners on all events
      if (arguments.length === 0) {
        var keys = objectKeys(events);
        var key;
        for (i = 0; i < keys.length; ++i) {
          key = keys[i];
          if (key === 'removeListener') continue;
          this.removeAllListeners(key);
        }
        this.removeAllListeners('removeListener');
        this._events = objectCreate(null);
        this._eventsCount = 0;
        return this;
      }

      listeners = events[type];

      if (typeof listeners === 'function') {
        this.removeListener(type, listeners);
      } else if (listeners) {
        // LIFO order
        for (i = listeners.length - 1; i >= 0; i--) {
          this.removeListener(type, listeners[i]);
        }
      }

      return this;
    };

function _listeners(target, type, unwrap) {
  var events = target._events;

  if (!events)
    return [];

  var evlistener = events[type];
  if (!evlistener)
    return [];

  if (typeof evlistener === 'function')
    return unwrap ? [evlistener.listener || evlistener] : [evlistener];

  return unwrap ? unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
}

EventEmitter.prototype.listeners = function listeners(type) {
  return _listeners(this, type, true);
};

EventEmitter.prototype.rawListeners = function rawListeners(type) {
  return _listeners(this, type, false);
};

EventEmitter.listenerCount = function(emitter, type) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(type);
  } else {
    return listenerCount.call(emitter, type);
  }
};

EventEmitter.prototype.listenerCount = listenerCount;
function listenerCount(type) {
  var events = this._events;

  if (events) {
    var evlistener = events[type];

    if (typeof evlistener === 'function') {
      return 1;
    } else if (evlistener) {
      return evlistener.length;
    }
  }

  return 0;
}

EventEmitter.prototype.eventNames = function eventNames() {
  return this._eventsCount > 0 ? Reflect.ownKeys(this._events) : [];
};

// About 1.5x faster than the two-arg version of Array#splice().
function spliceOne(list, index) {
  for (var i = index, k = i + 1, n = list.length; k < n; i += 1, k += 1)
    list[i] = list[k];
  list.pop();
}

function arrayClone(arr, n) {
  var copy = new Array(n);
  for (var i = 0; i < n; ++i)
    copy[i] = arr[i];
  return copy;
}

function unwrapListeners(arr) {
  var ret = new Array(arr.length);
  for (var i = 0; i < ret.length; ++i) {
    ret[i] = arr[i].listener || arr[i];
  }
  return ret;
}

function objectCreatePolyfill(proto) {
  var F = function() {};
  F.prototype = proto;
  return new F;
}
function objectKeysPolyfill(obj) {
  var keys = [];
  for (var k in obj) if (Object.prototype.hasOwnProperty.call(obj, k)) {
    keys.push(k);
  }
  return k;
}
function functionBindPolyfill(context) {
  var fn = this;
  return function () {
    return fn.apply(context, arguments);
  };
}

},{}],113:[function(require,module,exports){
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],114:[function(require,module,exports){
'use strict';

/**
 * Constants.
 */

var errorMessage;

errorMessage = 'An argument without append, prepend, ' +
    'or detach methods was given to `List';

/**
 * Creates a new List: A linked list is a bit like an Array, but
 * knows nothing about how many items are in it, and knows only about its
 * first (`head`) and last (`tail`) items. Each item (e.g. `head`, `tail`,
 * &c.) knows which item comes before or after it (its more like the
 * implementation of the DOM in JavaScript).
 * @global
 * @private
 * @constructor
 * @class Represents an instance of List.
 */

function List(/*items...*/) {
    if (arguments.length) {
        return List.from(arguments);
    }
}

var ListPrototype;

ListPrototype = List.prototype;

/**
 * Creates a new list from the arguments (each a list item) passed in.
 * @name List.of
 * @param {...ListItem} [items] - Zero or more items to attach.
 * @returns {list} - A new instance of List.
 */

List.of = function (/*items...*/) {
    return List.from.call(this, arguments);
};

/**
 * Creates a new list from the given array-like object (each a list item)
 * passed in.
 * @name List.from
 * @param {ListItem[]} [items] - The items to append.
 * @returns {list} - A new instance of List.
 */
List.from = function (items) {
    var list = new this(), length, iterator, item;

    if (items && (length = items.length)) {
        iterator = -1;

        while (++iterator < length) {
            item = items[iterator];

            if (item !== null && item !== undefined) {
                list.append(item);
            }
        }
    }

    return list;
};

/**
 * List#head
 * Default to `null`.
 */
ListPrototype.head = null;

/**
 * List#tail
 * Default to `null`.
 */
ListPrototype.tail = null;

/**
 * Returns the list's items as an array. This does *not* detach the items.
 * @name List#toArray
 * @returns {ListItem[]} - An array of (still attached) ListItems.
 */
ListPrototype.toArray = function () {
    var item = this.head,
        result = [];

    while (item) {
        result.push(item);
        item = item.next;
    }

    return result;
};

/**
 * Prepends the given item to the list: Item will be the new first item
 * (`head`).
 * @name List#prepend
 * @param {ListItem} item - The item to prepend.
 * @returns {ListItem} - An instance of ListItem (the given item).
 */
ListPrototype.prepend = function (item) {
    if (!item) {
        return false;
    }

    if (!item.append || !item.prepend || !item.detach) {
        throw new Error(errorMessage + '#prepend`.');
    }

    var self, head;

    // Cache self.
    self = this;

    // If self has a first item, defer prepend to the first items prepend
    // method, and return the result.
    head = self.head;

    if (head) {
        return head.prepend(item);
    }

    // ...otherwise, there is no `head` (or `tail`) item yet.

    // Detach the prependee.
    item.detach();

    // Set the prependees parent list to reference self.
    item.list = self;

    // Set self's first item to the prependee, and return the item.
    self.head = item;

    return item;
};

/**
 * Appends the given item to the list: Item will be the new last item (`tail`)
 * if the list had a first item, and its first item (`head`) otherwise.
 * @name List#append
 * @param {ListItem} item - The item to append.
 * @returns {ListItem} - An instance of ListItem (the given item).
 */

ListPrototype.append = function (item) {
    if (!item) {
        return false;
    }

    if (!item.append || !item.prepend || !item.detach) {
        throw new Error(errorMessage + '#append`.');
    }

    var self, head, tail;

    // Cache self.
    self = this;

    // If self has a last item, defer appending to the last items append
    // method, and return the result.
    tail = self.tail;

    if (tail) {
        return tail.append(item);
    }

    // If self has a first item, defer appending to the first items append
    // method, and return the result.
    head = self.head;

    if (head) {
        return head.append(item);
    }

    // ...otherwise, there is no `tail` or `head` item yet.

    // Detach the appendee.
    item.detach();

    // Set the appendees parent list to reference self.
    item.list = self;

    // Set self's first item to the appendee, and return the item.
    self.head = item;

    return item;
};

/**
 * Creates a new ListItem: A linked list item is a bit like DOM node:
 * It knows only about its "parent" (`list`), the item before it (`prev`),
 * and the item after it (`next`).
 * @global
 * @private
 * @constructor
 * @class Represents an instance of ListItem.
 */

function ListItem() {}

List.Item = ListItem;

var ListItemPrototype = ListItem.prototype;

ListItemPrototype.next = null;

ListItemPrototype.prev = null;

ListItemPrototype.list = null;

/**
 * Detaches the item operated on from its parent list.
 * @name ListItem#detach
 * @returns {ListItem} - The item operated on.
 */
ListItemPrototype.detach = function () {
    // Cache self, the parent list, and the previous and next items.
    var self = this,
        list = self.list,
        prev = self.prev,
        next = self.next;

    // If the item is already detached, return self.
    if (!list) {
        return self;
    }

    // If self is the last item in the parent list, link the lists last item
    // to the previous item.
    if (list.tail === self) {
        list.tail = prev;
    }

    // If self is the first item in the parent list, link the lists first item
    // to the next item.
    if (list.head === self) {
        list.head = next;
    }

    // If both the last and first items in the parent list are the same,
    // remove the link to the last item.
    if (list.tail === list.head) {
        list.tail = null;
    }

    // If a previous item exists, link its next item to selfs next item.
    if (prev) {
        prev.next = next;
    }

    // If a next item exists, link its previous item to selfs previous item.
    if (next) {
        next.prev = prev;
    }

    // Remove links from self to both the next and previous items, and to the
    // parent list.
    self.prev = self.next = self.list = null;

    // Return self.
    return self;
};

/**
 * Prepends the given item *before* the item operated on.
 * @name ListItem#prepend
 * @param {ListItem} item - The item to prepend.
 * @returns {ListItem} - The item operated on, or false when that item is not
 * attached.
 */
ListItemPrototype.prepend = function (item) {
    if (!item || !item.append || !item.prepend || !item.detach) {
        throw new Error(errorMessage + 'Item#prepend`.');
    }

    // Cache self, the parent list, and the previous item.
    var self = this,
        list = self.list,
        prev = self.prev;

    // If self is detached, return false.
    if (!list) {
        return false;
    }

    // Detach the prependee.
    item.detach();

    // If self has a previous item...
    if (prev) {
        // ...link the prependees previous item, to selfs previous item.
        item.prev = prev;

        // ...link the previous items next item, to self.
        prev.next = item;
    }

    // Set the prependees next item to self.
    item.next = self;

    // Set the prependees parent list to selfs parent list.
    item.list = list;

    // Set the previous item of self to the prependee.
    self.prev = item;

    // If self is the first item in the parent list, link the lists first item
    // to the prependee.
    if (self === list.head) {
        list.head = item;
    }

    // If the the parent list has no last item, link the lists last item to
    // self.
    if (!list.tail) {
        list.tail = self;
    }

    // Return the prependee.
    return item;
};

/**
 * Appends the given item *after* the item operated on.
 * @name ListItem#append
 * @param {ListItem} item - The item to append.
 * @returns {ListItem} - The item operated on, or false when that item is not
 * attached.
 */
ListItemPrototype.append = function (item) {
    // If item is falsey, return false.
    if (!item || !item.append || !item.prepend || !item.detach) {
        throw new Error(errorMessage + 'Item#append`.');
    }

    // Cache self, the parent list, and the next item.
    var self = this,
        list = self.list,
        next = self.next;

    // If self is detached, return false.
    if (!list) {
        return false;
    }

    // Detach the appendee.
    item.detach();

    // If self has a next item...
    if (next) {
        // ...link the appendees next item, to selfs next item.
        item.next = next;

        // ...link the next items previous item, to the appendee.
        next.prev = item;
    }

    // Set the appendees previous item to self.
    item.prev = self;

    // Set the appendees parent list to selfs parent list.
    item.list = list;

    // Set the next item of self to the appendee.
    self.next = item;

    // If the the parent list has no last item or if self is the parent lists
    // last item, link the lists last item to the appendee.
    if (self === list.tail || !list.tail) {
        list.tail = item;
    }

    // Return the appendee.
    return item;
};

/**
 * Expose `List`.
 */

module.exports = List;

},{}],115:[function(require,module,exports){
'use strict';

module.exports = require('./_source/linked-list.js');

},{"./_source/linked-list.js":114}],116:[function(require,module,exports){
'use strict';

var ERRORS = {
  NOLOGGEDUSER: 'No logged user',
  WRONGPARAMETER: 'One or several parameters are wrong',
  WRONGPASSPHRASE: 'The given passphrase is wrong',
  NOURLPROVIDED: 'No url provided',
  EMPTYUSERLIST: 'User list is empty',
  NOUSERNAME: 'No username provided',
  NOPASSPHRASE: 'No passphrase provided',
  EXISTINGUSERNAME: 'The username already exists',
  EXISTINGURL: 'The application url already exists',
  FUNCTIONNOTDEFINED: 'The function is not defined',
  USERNAMENOTFOUND: 'The username does not exist',
  NOEXISTINGKEY: 'The required key does not exist',
  NOVALUE: 'No value provided',
  NOTOKEN: 'Token does not exist',
  BADTOKEN: 'Token is not valid',
  BADREQUEST: 'Bad request',
  NOTAUTHORIZED: 'Not authorized',
  ENCRYPTIONERROR: 'Encryption error',
  DECRYPTIONERROR: 'Decryption error',
  NOIMPORTRULES: 'No import rules provided'

  /**
    * @typedef MasqError
    * @type {Object}
    * @property {boolean} error
    * @property {int} status - THe status of the error
    * @property {string} message - The status of the error
    * @property {string} name - The name of the error
    * @property {string} stack - The stack
    */

  /**
   * Use this fonction to check if the required parameters
   * are present in the received object.
   * @param {object} obj - The object we want to check
   * @param {array} parameters - The array with all the keys we want to test
   * @returns {masqError}
   */
};var checkObject = function checkObject(obj, parameters) {
  for (var i in parameters) {
    if (typeof obj[parameters[i]] !== 'boolean') {
      if (!obj[parameters[i]] || obj[parameters[i]] === '') {
        var error = {
          message: 'The parameter ' + parameters[i] + ' is required',
          name: ERRORS.WRONGPARAMETER,
          error: true
        };
        throw error;
      }
    }
  }
};

/**
 * Generate a masqError object, the name must be
 * one of ERRORS.
 *
 * @param {string} name - The name of the error
 * @param {string} message
 * @param {string} status
 */
var generateError = function generateError(name, message, status) {
  var err = {
    name: name || '',
    message: message || '',
    status: status || '',
    error: true
  };
  return err;
};

// export default toArray
// export { checkObject, generateError, ERRORS, toArray, bufferToHexString, toString, hexStringToBuffer, deriveKey, randomString }
module.exports.ERRORS = ERRORS;
module.exports.generateError = generateError;
module.exports.checkObject = checkObject;
'use strict';

/**
 * Genreate a UUID
 * @param {int} len - Length of string to be generated
 * @returns {string} - The generated uuid
 */
var generateUUID = function generateUUID() {
  var len = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 32;

  var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz'.split('');
  if (typeof len !== "number") {
    len = 32;
  }
  var str = '';
  for (var i = 0; i < len; i++) {
    str += chars[Math.floor(Math.random() * chars.length)];
  }
  return str;
};

module.exports.generateUUID = generateUUID;

},{}],117:[function(require,module,exports){
'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }(); /* global crypto */


var _utils = require('./utils.js');

var utils = _interopRequireWildcard(_utils);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var aesModes = {
  CBC: 'aes-cbc',
  GCM: 'aes-gcm',
  CTR: 'aes-ctr'
};

var acceptedMode = ['aes-cbc', 'aes-gcm', 'aes-ctr'];

var acceptedKeySize = [128, 192, 256];

/**
 * Decrypt data
 *
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {ArrayBuffer} key - The AES key as raw data. 128 or 256 bits
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only aes-gcm)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The decrypted buffer
 */
var decryptBuffer = function decryptBuffer(data, key, cipherContext) {
  // TODO: test input params
  return crypto.subtle.decrypt(cipherContext, key, data).then(function (result) {
    return new Uint8Array(result);
  });
};

/**
 * Encrypt data
 *
 * @param {ArrayBuffer} data - Data to encrypt
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only aes-gcm)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The encrypted buffer
 */
var encryptBuffer = function encryptBuffer(data, key, cipherContext) {
  return crypto.subtle.encrypt(cipherContext, key, data).then(function (result) {
    return new Uint8Array(result);
  });
};
/**
 * AES cipher
 * @constructor
 * @param {Object} params - The AES cipher parameters
 * @param {string} [params.mode] - The encryption mode : aes-gcm, aes-cbc
 * @param {ArrayBuffer} [params.key] - The AES CryptoKey
 * @param {number} [params.keySize] - The key size in bits (128, 192, 256)
 * @param {number} [params.iv] - The IV, if not provided it will be generated randomly
 * @param {number} [params.length] - The counter length for aes-ctr mode
 * @param {string} [params.additionalData] - The authenticated data, only for aes-gcm mode.
 */

var AES = function () {
  function AES(params) {
    _classCallCheck(this, AES);

    this.mode = params.mode || 'aes-gcm';
    this.keySize = params.keySize || 128;
    this.IV = params.iv || null;
    this.key = params.key || null;
    this.length = params.length || 128;
    this.additionalData = params.additionalData || '';
  }

  _createClass(AES, [{
    key: 'checkRaw',


    /**
    * Check the received key format (CryptoKey or raw key).
    * If raw, import the key and return the CryptoKey
    *
    * @param {obj} obj - Save this in obj
    * @returns {CryptoKey|arrayBuffer} - The CryptoKey
    */
    value: function checkRaw(obj, key) {
      return new Promise(function (resolve, reject) {
        if (key instanceof Uint8Array) {
          obj.importKeyRaw(key).then(resolve);
        } else {
          resolve(key);
        }
      });
    }

    /**
    * Transform a CryptoKey into a raw key
    *
    * @param {CryptoKey} key - The CryptoKey
    * @returns {arrayBuffer} - The raw key
    */

  }, {
    key: 'exportKeyRaw',
    value: function exportKeyRaw() {
      var key = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : this._key;
      var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'raw';

      return crypto.subtle.exportKey(type, key).then(function (key) {
        return new Uint8Array(key);
      });
    }

    /**
    * Transform a raw key into a CryptoKey
    *
    * @param {arrayBuffer} key - The key we want to import
    * @returns {CryptoKey} - The CryptoKey
    */

  }, {
    key: 'importKeyRaw',
    value: function importKeyRaw(key) {
      var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'raw';

      return crypto.subtle.importKey(type, key, {
        name: this.mode
      }, true, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
    }

    /**
    * Decrypt the given input. All cipher context information
    * have been initialized at object creation (default or parameter)
    *
    * @param {object} input - The ciphertext and associated decryption data
    * @param {hexString} input.ciphertext - The ciphertext
    * @param {hexString} input.iv - The IV used at encryption
    * @param {hexString} [input.version] - The additionnal data for aes-gcm mode
    * @returns {string} - The decrypted input
    */

  }, {
    key: 'decrypt',
    value: function decrypt(input) {
      // Prepare context, all modes have at least one property : ciphertext
      var context = {};
      var cipherContext = {};
      context.ciphertext = input.hasOwnProperty('ciphertext') ? utils.hexStringToBuffer(input.ciphertext) : '';
      if (this.mode === 'aes-gcm') {
        context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : '';
        // aes-gcm may have an additional authenticated data property (optional)
        context.additionalData = input.hasOwnProperty('version') ? utils.toArray(input.version) : [];
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.iv = context.iv;
        cipherContext.additionalData = context.additionalData;
        // This function test the given key and return the Cryptokey
        return this.checkRaw(this, this.key).then(function (key) {
          return decryptBuffer(context.ciphertext, key, cipherContext);
        }).then(function (res) {
          return utils.toString(res);
        });
      } else if (this.mode === 'aes-cbc') {
        // IV is 128 bits long === 16 bytes
        context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : '';
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.iv = context.iv;
        return this.checkRaw(this, this.key).then(function (key) {
          return decryptBuffer(context.ciphertext, key, cipherContext);
        }).then(function (res) {
          return utils.toString(res);
        });
      } else if (this.mode === 'aes-ctr') {
        // IV is 128 bits long === 16 bytes
        context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : '';
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.counter = context.iv;
        cipherContext.length = this.length;
        return this.checkRaw(this, this.key).then(function (key) {
          return decryptBuffer(context.ciphertext, key, cipherContext);
        }).then(function (res) {
          return utils.toString(res);
        });
      } else {
        throw new Error('The mode ' + this.mode + ' is not yet supported');
      }
    }

    /**
    * Encrypt the given input. All cipher context information
    * have been initialized at object creation (as default or as parameter)
    * If the input is an object, it has to be stringified
    *
    * @param {string} input - The plaintext
    * @returns {object} - The encrypted input with additional cipher information (e.g. iv)
    */

  }, {
    key: 'encrypt',
    value: function encrypt(input) {
      // all modes have at least the plaintext
      var context = {};
      var cipherContext = {};
      context.plaintext = utils.toArray(input);
      if (this.mode === 'aes-gcm') {
        // IV is 96 bits long === 12 bytes
        context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(12));
        context.additionalData = utils.toArray(this.additionalData);
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.iv = context.iv;
        cipherContext.additionalData = context.additionalData;
        // This function tests the given key and return the Cryptokey
        return this.checkRaw(this, this.key).then(function (key) {
          return encryptBuffer(context.plaintext, key, cipherContext);
        }).then(function (result) {
          return {
            ciphertext: utils.bufferToHexString(result),
            iv: utils.bufferToHexString(context.iv),
            version: utils.toString(context.additionalData)
          };
        });
      } else if (this.mode === 'aes-cbc') {
        // IV is 128 bits long === 16 bytes
        context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(16));
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.iv = context.iv;
        return this.checkRaw(this, this.key).then(function (key) {
          return encryptBuffer(context.plaintext, key, cipherContext);
        }).then(function (result) {
          return {
            ciphertext: utils.bufferToHexString(result),
            iv: utils.bufferToHexString(context.iv)
          };
        });
      } else if (this.mode === 'aes-ctr') {
        // IV is 128 bits long === 16 bytes
        context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(16));
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.counter = context.iv;
        cipherContext.length = this.length;
        return this.checkRaw(this, this.key).then(function (key) {
          return encryptBuffer(context.plaintext, key, cipherContext);
        }).then(function (result) {
          return {
            ciphertext: utils.bufferToHexString(result),
            iv: utils.bufferToHexString(context.iv)
          };
        });
      } else {
        throw new Error('The mode ' + this.mode + ' is not yet supported');
      }
    }

    /**
     * Generate an AES key based on the cipher mode and keysize
     * Cipher mode and key size are initialized at cipher AES instance creation.
     *
     * @returns {CryptoKey} - The generated AES key.
     */

  }, {
    key: 'genAESKey',
    value: function genAESKey() {
      return crypto.subtle.generateKey({
        name: this.mode || 'aes-gcm',
        length: this.keySize || 128
      }, true, ['decrypt', 'encrypt']);
    }

    /**
    * Wrap the given key. All cipher context information of the wrapping key
    * have been initialized at object creation (default or parameter)
    * Return the wrappedKey and the associated iv.
    *
    * @param {CryptoKey} toBeWrappedKey - The key we want to wrap
    * @param {string} [keySize] - The size of the key we want to wrap
    * @param {string} [exportType] - The export format of the toBeWrappedKey
    * @returns {Uint8Array} - The wrapped key
    */

  }, {
    key: 'wrapKey',
    value: function wrapKey(toBeWrappedKey, keySize, exportType) {
      var _this = this;

      var iv = window.crypto.getRandomValues(new Uint8Array(12));
      return this.checkRaw(this, this.key).then(function (instanceKey) {
        return crypto.subtle.wrapKey(exportType || 'raw', toBeWrappedKey, instanceKey, {
          name: _this.mode || 'aes-gcm',
          iv: iv,
          additionalData: utils.toArray('')
        });
      }).then(function (wrappedKey) {
        return {
          encryptedMasterKey: new Uint8Array(wrappedKey),
          iv: iv,
          keySize: keySize || 128
        };
      });
    }

    /**
    * Unwrap the given key. All cipher context information of the wrapping key
    * have been initialized at object creation (default or parameter)
    *
    * @param {Uint8array} wrappedKey - The wrapped key
    * @param {Uint8Array} iv - The iv
    * @param {Uint8Array} keySize - The size of the unwrapped key (same as before wrapping)
    * @param {string} [importType] - The import format of the wrappedKey, must be the same as in wrap.
    * @returns {CryptoKey} - The decrypted input
    */

  }, {
    key: 'unwrapKey',
    value: function unwrapKey(wrappedKey, iv, keySize, importType) {
      var _this2 = this;

      return this.checkRaw(this, this.key).then(function (instanceKey) {
        return crypto.subtle.unwrapKey(importType || 'raw', wrappedKey, instanceKey, {
          name: _this2.mode || 'aes-gcm',
          iv: iv,
          additionalData: utils.toArray('')
        }, {
          name: _this2.mode || 'aes-gcm',
          length: keySize || 128
        }, true, ['encrypt', 'decrypt']);
      });
    }
  }, {
    key: 'additionalData',
    get: function get() {
      return this._additionalData;
    },
    set: function set(newAdditionalData) {
      if (typeof newAdditionalData === 'string') {
        this._additionalData = newAdditionalData;
      } else {
        throw new Error("You did not provide a string for additional data, default value is ''.");
      }
    }
  }, {
    key: 'key',
    get: function get() {
      return this._key;
    },
    set: function set(newKey) {
      this._key = newKey;
    }
  }, {
    key: 'mode',
    get: function get() {
      return this._mode;
    },
    set: function set(newMode) {
      if (acceptedMode.includes(newMode)) {
        this._mode = newMode;
      } else {
        throw new Error('Accepted modes are ' + acceptedMode.join(', '));
      }
    }
  }, {
    key: 'keySize',
    get: function get() {
      return this._keySize;
    },
    set: function set(newKeySize) {
      if (acceptedKeySize.includes(newKeySize)) {
        this._keySize = newKeySize;
      } else {
        throw new Error('Accepted keySize are ' + acceptedKeySize.join(', '));
      }
    }
  }]);

  return AES;
}();

module.exports.AES = AES;
module.exports.aesModes = aesModes;
},{"./utils.js":121}],118:[function(require,module,exports){
'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/* global crypto */

var acceptedCurve = ['P-256', 'P-384', 'P-521'];
var acceptedAlgName = ['ECDH', 'ECDSA'];

/**
 * Elliptic Curve
 * @constructor
 * @param {Object} params - The EC cipher parameters
 * @param {string} params.name - The algorithm name ("ECDH" or "ECDSA")
 * @param {string} [params.hash] - The hash function (sign/verif). Default : "SHA-256", possible values: "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
 * @param {string} [params.curve] - The elliptic curve ("P-256", "P-384", or "P-521")
 */

var EC = function () {
  function EC(params) {
    _classCallCheck(this, EC);

    this.name = params.name || 'ECDH';
    this.curve = params.curve || 'P-384';
    this.hash = params.hash || 'SHA-256';
    this.publicKey = null;
    this.privateKey = null;
  }

  _createClass(EC, [{
    key: 'genECKeyPair',


    /**
     * Generate an EC key pair and store them in the class instance
     *
     * @returns {CryptoKey} - The generated EC key Pair as CryptoKey
     */
    value: function genECKeyPair() {
      var _this = this;

      return crypto.subtle.generateKey({
        name: this.name,
        namedCurve: this.curve
      }, false, this.name === 'ECDH' ? ['deriveKey', 'deriveBits'] : ['sign', 'verify']).then(function (cryptoKey) {
        _this.publicKey = cryptoKey.publicKey;
        _this.privateKey = cryptoKey.privateKey;
        return cryptoKey;
      }).catch(function (err) {
        if (err.code === 9) {
          throw new Error('WebCrypto API error :\n - During ECDH key generation: given namedCurve parameter is not accepted');
        } else {
          throw new Error(err);
        }
      });
    }

    /**
    * Check the received key format (CryptoKey or raw key).
    * If raw, import the key and return the CryptoKey
    *
    * @param {obj} obj - Save this in obj
    * @param {CryptoKey|arrayBuffer} key - The key
    * @returns {CryptoKey|arrayBuffer} - The CryptoKey
    */

  }, {
    key: 'checkRaw',
    value: function checkRaw(obj, key) {
      return new Promise(function (resolve, reject) {
        if (key instanceof Uint8Array) {
          obj.importKeyRaw(key).then(resolve);
        } else {
          resolve(key);
        }
      });
    }

    /**
     * Derive  key (AES-GCM by default) during ECDH key exchange
     * The private EC key is already in EC.privateKey
     *
     * @param {Cryptokey|arrayBuffer} publicKey Public Key of the sender (verified)
     * @param {string} type Key type of the derived key (aes-cbc, aes-gcm)
     * @param {int} keySize Key size of the derived key in bits (128, 192, 256)
     * @param {CryptoKey} [privateKey] The EC private key if not generated via genECKeyPair
     * @returns {arrayBuffer} The derived key
     */

  }, {
    key: 'deriveKeyECDH',
    value: function deriveKeyECDH(publicKey) {
      var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'aes-gcm';

      var _this2 = this;

      var keySize = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 128;
      var privateKey = arguments[3];

      return this.checkRaw(this, publicKey).then(function (key) {
        return crypto.subtle.deriveKey({
          name: _this2.name,
          public: key
        }, privateKey || _this2.privateKey, {
          name: type,
          length: keySize
        }, true, ['decrypt', 'encrypt']);
      }).then(function (derivedKey) {
        return crypto.subtle.exportKey('raw', derivedKey);
      }).then(function (rawKey) {
        return new Uint8Array(rawKey);
      });
    }

    /**
     * Export raw key
     * The public key is already stored in EC.publicKey
     *
     * {CryptoKey} key - The key that we extract raw value (available in EC.publicKey)
     * @returns {arrayBuffer} The raw key
     */

  }, {
    key: 'exportKeyRaw',
    value: function exportKeyRaw(key) {
      return crypto.subtle.exportKey('raw', key || this.publicKey).then(function (rawKey) {
        return new Uint8Array(rawKey);
      });
    }

    /**
     * Import raw key
     *
     * @param {CryptoKey} key - The key that we extract raw value
     * @param {String} curve - The elliptic curve used at the imported key creation
     * @returns {Promise} - The CryptoKey
     */

  }, {
    key: 'importKeyRaw',
    value: function importKeyRaw(key, curve, algName) {
      return crypto.subtle.importKey('raw', key, {
        name: algName || this.name,
        namedCurve: curve || this.curve
      }, true, []);
    }

    /**
     * Sign data
     * EC private key could be already stored in EC.privateKey
     *
     * @param {arrayBuffer} data - The data to be signed
     * @param {CryptoKey} privateKey - The private key (if nt sotred in EC class)
     * @param {String} [hash] - The hash function used for signature. Default 'SHA-256'
     * @returns {arrayBuffer} - The signature
     */

  }, {
    key: 'signEC',
    value: function signEC(data, privateKey, hash) {
      return crypto.subtle.sign({
        name: 'ECDSA',
        hash: { name: hash || this.hash }
      }, privateKey || this.privateKey, data).then(function (signature) {
        return new Uint8Array(signature);
      });
    }

    /**
     * Verif signature
     *
     * @param {CryptoKey} publicKey - The public RSA Key used to verify data signature
     * @param {arrayBuffer} signature - The signature
     * @param {arrayBuffer} signedData - Signed data
     * @param {String} [hash] - The hash function used for signature. Default 'SHA-256'
     * @returns {boolean} - Result
     */

  }, {
    key: 'verifEC',
    value: function verifEC(publicKey, signature, signedData, hash) {
      return crypto.subtle.verify({
        name: 'ECDSA',
        hash: { name: hash || this.hash }
      }, publicKey, signature, signedData);
    }
  }, {
    key: 'curve',
    get: function get() {
      return this._curve;
    },
    set: function set(newCurve) {
      if (acceptedCurve.includes(newCurve)) {
        this._curve = newCurve;
      } else {
        throw new Error('Accepted curves are ' + acceptedCurve.join(', '));
      }
    }
  }, {
    key: 'name',
    get: function get() {
      return this._name;
    },
    set: function set(newName) {
      if (acceptedAlgName.includes(newName)) {
        this._name = newName;
      } else {
        throw new Error('Accepted names are ' + acceptedAlgName.join(', '));
      }
    }
  }]);

  return EC;
}();

module.exports.EC = EC;
},{}],119:[function(require,module,exports){
'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/* global crypto */

/**
   * Verif data (e.g. raw EC public key in case of ECDH)
   *
   * @param {CryptoKey} publicKey - The public RSA Key used to verify data signature
   * @param {arrayBuffer} signature - The signature
   * @param {arrayBuffer} signedData - Signed data
   * @returns {boolean} - Result
   */
var _verifRSA = function _verifRSA(publicKey, signature, signedData) {
  return crypto.subtle.verify({
    name: 'RSA-PSS',
    saltLength: 16
  }, publicKey, signature, signedData);
};

/**
   * Import RSA-PSS public key
   *
   * @param {jwk} key - The key (jwk format) that we want to import
   * @param {jwk} name - The algorithm name of the imported RSA key (default : "RSA-PSS")
   * @param {jwk} hash - The hash name of the imported RSA key (default : "SHA-256")
   * @returns {Promise} - The imported key as CryptoKey
   */
var _importRSAPubKey = function _importRSAPubKey(key, name, hash) {
  return crypto.subtle.importKey('jwk', {
    kty: key.kty,
    e: key.e,
    n: key.n,
    alg: key.alg,
    ext: key.ext
  }, {
    name: name || 'RSA-PSS',
    hash: {
      name: hash || 'SHA-256'
    }
  }, false, ['verify']);
};

/**
 * RSA
 * @constructor
 * @param {Object} params - The RSA cipher parameters
 * @param {string} params.hash The hash function ("SHA-256", "SHA-384", "SHA-512")
 * @param {string} params.name The algorithm name  ("RSA-PSS")
 * @param {string} params.modulusLength - The modulus length (4096 default)
 */

var RSA = function () {
  function RSA(params) {
    _classCallCheck(this, RSA);

    this.modulusLength = params.modulusLength || 4096;
    this.hash = params.hash || 'SHA-256';
    this.name = params.name || 'RSA-PSS';
    this.publicKey = null;
    this.privateKey = null;
  }

  _createClass(RSA, [{
    key: 'genRSAKeyPair',


    /**
     * Generate a RSA-PSS key pair for signature and verification
     *
     * @param {int} modulusLength - The modulus length (1024, 2048 or 4096)
     * @returns {Promise} - The RSA key pair : publicKey and privateKey
     */
    value: function genRSAKeyPair() {
      var _this = this;

      var modulusLength = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 4096;

      return crypto.subtle.generateKey({
        name: 'RSA-PSS',
        modulusLength: modulusLength, // can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {
          name: 'SHA-256'
        }
      }, false, ['sign', 'verify']).then(function (cryptoKey) {
        _this._publicKey = cryptoKey.publicKey;
        _this._privateKey = cryptoKey.privateKey;
        return cryptoKey;
      });
    }

    /**
     * Verif data (e.g. raw EC public key in case of ECDH)
     *
     * @param {CryptoKey} publicKey - The public RSA Key used to verify data signature
     * @param {arrayBuffer} signature - The signature
     * @param {arrayBuffer} signedData - Signed data
     * @returns {boolean} - Result
     */

  }, {
    key: 'verifRSA',
    value: function verifRSA(publicKey, signature, signedData) {
      return _verifRSA(publicKey, signature, signedData);
    }

    /**
     * Sign data (e.g. raw EC public key in case of ECDH)
     * RSA private key is already stored in RSA.privateKey
     *
     * @param {arrayBuffer} data - The data to be signed
     * @param {CryptoKey} privateKey - The private key (if nt sotred in RSA class)
     * @returns {arrayBuffer} - The signature
     */

  }, {
    key: 'signRSA',
    value: function signRSA(data, privateKey) {
      return crypto.subtle.sign({
        name: 'RSA-PSS',
        saltLength: 16
      }, privateKey || this.privateKey, data).then(function (signature) {
        return new Uint8Array(signature);
      });
    }

    /**
     * Import RSA-PSS public key
     *
     * @param {jwk} key - The key (jwk format) that we want to import
     * @param {jwk} name - The algorithm name of the imported RSA key (default : "RSA-PSS")
     * @param {jwk} hash - The hash name of the imported RSA key (default : "SHA-256")
     * @returns {Promise} - The imported key as CryptoKey
     */

  }, {
    key: 'importRSAPubKey',
    value: function importRSAPubKey(key, name, hash) {
      var _this2 = this;

      _importRSAPubKey(key, name, hash).then(function (key) {
        _this2.publicKey = key;
      });
    }

    /**
     * Export RSA-PSS public raw key
     * Do not forget to stringify the exported key to compute
     * its hash or to store it.
     *
     * @param {CryptoKey} key - The key that we extract raw value
     * @param {string} format - The format ([jwk], spki)
     * @returns {Promise<Object>} - The key
     */

  }, {
    key: 'exportRSAPubKey',
    value: function exportRSAPubKey(key, format) {
      return crypto.subtle.exportKey(format || 'jwk', key || this.publicKey);
    }
  }, {
    key: 'publicKey',
    get: function get() {
      return this._publicKey;
    },
    set: function set(key) {
      this._publicKey = key;
    }
  }, {
    key: 'privateKey',
    get: function get() {
      return this._privateKey;
    },
    set: function set(key) {
      this._privateKey = key;
    }
  }]);

  return RSA;
}();

module.exports.RSA = RSA;
module.exports.RSA.verifRSA = _verifRSA;
module.exports.RSA.importRSAPubKey = _importRSAPubKey;
},{}],120:[function(require,module,exports){
'use strict';

var _AES = require('./AES');

var _AES2 = _interopRequireDefault(_AES);

var _EC = require('./EC');

var _EC2 = _interopRequireDefault(_EC);

var _RSA = require('./RSA');

var _RSA2 = _interopRequireDefault(_RSA);

var _utils = require('./utils');

var _utils2 = _interopRequireDefault(_utils);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

module.exports.AES = _AES2.default.AES;
module.exports.aesModes = _AES2.default.aesModes;
module.exports.EC = _EC2.default.EC;
module.exports.RSA = _RSA2.default.RSA;
module.exports.utils = _utils2.default;
},{"./AES":117,"./EC":118,"./RSA":119,"./utils":121}],121:[function(require,module,exports){
'use strict';

/* global crypto */

/**
 * Convert ascii to ArrayBufffer
 * ex : "bonjour" -> Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ]
 *
 * @param {String} str
 * @returns {ArrayBuffer}
 */
var toArray = function toArray(str) {
  if (typeof str !== 'string') {
    throw new Error('toArray accepts only string');
  }
  var chars = [];
  for (var i = 0; i < str.length; ++i) {
    chars.push(str.charCodeAt(i));
  }
  return new Uint8Array(chars);
};

/**
* Convert ArrayBufffer to hex String
* ex : Uint8Array [ 17, 161, 178 ] -> '11a1b2'
*
* @param {ArrayBuffer} bytes
* @returns {String}
*/
var bufferToHexString = function bufferToHexString(bytes) {
  if (!bytes) {
    return null;
  }
  var hexBytes = [];

  for (var i = 0; i < bytes.length; ++i) {
    var byteString = bytes[i].toString(16);
    if (byteString.length < 2) {
      byteString = '0' + byteString;
    }
    hexBytes.push(byteString);
  }

  return hexBytes.join('');
};

/**
 * Convert ArrayBufffer to ascii
 * ex : Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ] -> "bonjour"
 *
 * @param {ArrayBuffer} bytes
 * @returns {String}
 */
var toString = function toString(bytes) {
  return String.fromCharCode.apply(null, new Uint8Array(bytes));
};

/**
 * Convert hex String to ArrayBufffer
 * ex : '11a1b2' -> Uint8Array [ 17, 161, 178 ]
 *
 * @param {String} hexString
 * @returns {ArrayBuffer}
 */
var hexStringToBuffer = function hexStringToBuffer(hexString) {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hexString');
  }
  var arrayBuffer = new Uint8Array(hexString.length / 2);

  for (var i = 0; i < hexString.length; i += 2) {
    var byteValue = parseInt(hexString.substr(i, 2), 16);
    if (isNaN(byteValue)) {
      throw new Error('Invalid hexString');
    }
    arrayBuffer[i / 2] = byteValue;
  }

  return arrayBuffer;
};

/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The passphrase length
 * @returns {Promise}   A promise that contains the derived key
 */
var deriveKey = function deriveKey(passPhrase, salt) {
  var iterations = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 10000;

  // Always specify a strong salt
  if (iterations < 10000) {
    console.warn('The iteration number is less than 10000, increase it !');
  }

  return crypto.subtle.importKey('raw', typeof passPhrase === 'string' ? toArray(passPhrase) : passPhrase, 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (baseKey) {
    return crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: salt || new Uint8Array([]),
      iterations: iterations,
      hash: 'sha-256'
    }, baseKey, 128);
  }).then(function (derivedKey) {
    return new Uint8Array(derivedKey);
  });
};

/**
 * Hash of a string or arrayBuffer
 *
 * @param {string | arrayBuffer} msg The message
 * @param {string} [type] The hash name (SHA-256 by default)
 * @returns {Promise}   A promise that contains the hash as a Uint8Array
 */
var hash = function hash(msg) {
  var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'SHA-256';

  return window.crypto.subtle.digest({
    name: 'SHA-256'
  }, typeof msg === 'string' ? toArray(msg) : msg).then(function (digest) {
    return new Uint8Array(digest);
  });
};

// Generate a random string using the Webwindow API instead of Math.random
// (insecure)
var randomString = function randomString() {
  var length = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 18;

  var charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var result = '';
  if (window.crypto && window.crypto.getRandomValues) {
    var values = new Uint32Array(length);
    window.crypto.getRandomValues(values);
    for (var i = 0; i < length; i++) {
      result += charset[values[i] % charset.length];
    }
  } else {
    throw new Error("Your browser can't generate secure random numbers");
  }
  return result;
};

/**
   * Generate an AES key based on the cipher mode and keysize
   *
   * @returns {CryptoKey} - The generated AES key.
   */
var genAESKey = function genAESKey() {
  var mode = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 'aes-gcm';
  var keySize = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 128;

  return crypto.subtle.generateKey({
    name: mode,
    length: keySize
  }, true, ['decrypt', 'encrypt']);
};
/**
   * Generate an AES key based on the cipher mode and keysize
   *
   * @returns {CryptoKey} - The generated AES key.
   */
var genAESKeyRaw = function genAESKeyRaw() {
  var mode = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 'aes-gcm';
  var keySize = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 128;

  return genAESKey(mode, keySize).then(function (key) {
    return crypto.subtle.exportKey('raw', key).then(function (key) {
      return new Uint8Array(key);
    });
  });
};

module.exports = {
  toArray: toArray,
  bufferToHexString: bufferToHexString,
  toString: toString,
  hexStringToBuffer: hexStringToBuffer,
  deriveKey: deriveKey,
  randomString: randomString,
  hash: hash,
  genAESKey: genAESKey,
  genAESKeyRaw: genAESKeyRaw
};
},{}],122:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

// If obj.hasOwnProperty has been overridden, then calling
// obj.hasOwnProperty(prop) will break.
// See: https://github.com/joyent/node/issues/1707
function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

module.exports = function(qs, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var obj = {};

  if (typeof qs !== 'string' || qs.length === 0) {
    return obj;
  }

  var regexp = /\+/g;
  qs = qs.split(sep);

  var maxKeys = 1000;
  if (options && typeof options.maxKeys === 'number') {
    maxKeys = options.maxKeys;
  }

  var len = qs.length;
  // maxKeys <= 0 means that we should not limit keys count
  if (maxKeys > 0 && len > maxKeys) {
    len = maxKeys;
  }

  for (var i = 0; i < len; ++i) {
    var x = qs[i].replace(regexp, '%20'),
        idx = x.indexOf(eq),
        kstr, vstr, k, v;

    if (idx >= 0) {
      kstr = x.substr(0, idx);
      vstr = x.substr(idx + 1);
    } else {
      kstr = x;
      vstr = '';
    }

    k = decodeURIComponent(kstr);
    v = decodeURIComponent(vstr);

    if (!hasOwnProperty(obj, k)) {
      obj[k] = v;
    } else if (isArray(obj[k])) {
      obj[k].push(v);
    } else {
      obj[k] = [obj[k], v];
    }
  }

  return obj;
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

},{}],123:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var stringifyPrimitive = function(v) {
  switch (typeof v) {
    case 'string':
      return v;

    case 'boolean':
      return v ? 'true' : 'false';

    case 'number':
      return isFinite(v) ? v : '';

    default:
      return '';
  }
};

module.exports = function(obj, sep, eq, name) {
  sep = sep || '&';
  eq = eq || '=';
  if (obj === null) {
    obj = undefined;
  }

  if (typeof obj === 'object') {
    return map(objectKeys(obj), function(k) {
      var ks = encodeURIComponent(stringifyPrimitive(k)) + eq;
      if (isArray(obj[k])) {
        return map(obj[k], function(v) {
          return ks + encodeURIComponent(stringifyPrimitive(v));
        }).join(sep);
      } else {
        return ks + encodeURIComponent(stringifyPrimitive(obj[k]));
      }
    }).join(sep);

  }

  if (!name) return '';
  return encodeURIComponent(stringifyPrimitive(name)) + eq +
         encodeURIComponent(stringifyPrimitive(obj));
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

function map (xs, f) {
  if (xs.map) return xs.map(f);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    res.push(f(xs[i], i));
  }
  return res;
}

var objectKeys = Object.keys || function (obj) {
  var res = [];
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) res.push(key);
  }
  return res;
};

},{}],124:[function(require,module,exports){
'use strict';

exports.decode = exports.parse = require('./decode');
exports.encode = exports.stringify = require('./encode');

},{"./decode":122,"./encode":123}],125:[function(require,module,exports){
/**
 * Copyright (c) 2014-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// This method of obtaining a reference to the global object needs to be
// kept identical to the way it is obtained in runtime.js
var g = (function() { return this })() || Function("return this")();

// Use `getOwnPropertyNames` because not all browsers support calling
// `hasOwnProperty` on the global `self` object in a worker. See #183.
var hadRuntime = g.regeneratorRuntime &&
  Object.getOwnPropertyNames(g).indexOf("regeneratorRuntime") >= 0;

// Save the old regeneratorRuntime in case it needs to be restored later.
var oldRuntime = hadRuntime && g.regeneratorRuntime;

// Force reevalutation of runtime.js.
g.regeneratorRuntime = undefined;

module.exports = require("./runtime");

if (hadRuntime) {
  // Restore the original runtime.
  g.regeneratorRuntime = oldRuntime;
} else {
  // Remove the global property added by runtime.js.
  try {
    delete g.regeneratorRuntime;
  } catch(e) {
    g.regeneratorRuntime = undefined;
  }
}

},{"./runtime":126}],126:[function(require,module,exports){
/**
 * Copyright (c) 2014-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

!(function(global) {
  "use strict";

  var Op = Object.prototype;
  var hasOwn = Op.hasOwnProperty;
  var undefined; // More compressible than void 0.
  var $Symbol = typeof Symbol === "function" ? Symbol : {};
  var iteratorSymbol = $Symbol.iterator || "@@iterator";
  var asyncIteratorSymbol = $Symbol.asyncIterator || "@@asyncIterator";
  var toStringTagSymbol = $Symbol.toStringTag || "@@toStringTag";

  var inModule = typeof module === "object";
  var runtime = global.regeneratorRuntime;
  if (runtime) {
    if (inModule) {
      // If regeneratorRuntime is defined globally and we're in a module,
      // make the exports object identical to regeneratorRuntime.
      module.exports = runtime;
    }
    // Don't bother evaluating the rest of this file if the runtime was
    // already defined globally.
    return;
  }

  // Define the runtime globally (as expected by generated code) as either
  // module.exports (if we're in a module) or a new, empty object.
  runtime = global.regeneratorRuntime = inModule ? module.exports : {};

  function wrap(innerFn, outerFn, self, tryLocsList) {
    // If outerFn provided and outerFn.prototype is a Generator, then outerFn.prototype instanceof Generator.
    var protoGenerator = outerFn && outerFn.prototype instanceof Generator ? outerFn : Generator;
    var generator = Object.create(protoGenerator.prototype);
    var context = new Context(tryLocsList || []);

    // The ._invoke method unifies the implementations of the .next,
    // .throw, and .return methods.
    generator._invoke = makeInvokeMethod(innerFn, self, context);

    return generator;
  }
  runtime.wrap = wrap;

  // Try/catch helper to minimize deoptimizations. Returns a completion
  // record like context.tryEntries[i].completion. This interface could
  // have been (and was previously) designed to take a closure to be
  // invoked without arguments, but in all the cases we care about we
  // already have an existing method we want to call, so there's no need
  // to create a new function object. We can even get away with assuming
  // the method takes exactly one argument, since that happens to be true
  // in every case, so we don't have to touch the arguments object. The
  // only additional allocation required is the completion record, which
  // has a stable shape and so hopefully should be cheap to allocate.
  function tryCatch(fn, obj, arg) {
    try {
      return { type: "normal", arg: fn.call(obj, arg) };
    } catch (err) {
      return { type: "throw", arg: err };
    }
  }

  var GenStateSuspendedStart = "suspendedStart";
  var GenStateSuspendedYield = "suspendedYield";
  var GenStateExecuting = "executing";
  var GenStateCompleted = "completed";

  // Returning this object from the innerFn has the same effect as
  // breaking out of the dispatch switch statement.
  var ContinueSentinel = {};

  // Dummy constructor functions that we use as the .constructor and
  // .constructor.prototype properties for functions that return Generator
  // objects. For full spec compliance, you may wish to configure your
  // minifier not to mangle the names of these two functions.
  function Generator() {}
  function GeneratorFunction() {}
  function GeneratorFunctionPrototype() {}

  // This is a polyfill for %IteratorPrototype% for environments that
  // don't natively support it.
  var IteratorPrototype = {};
  IteratorPrototype[iteratorSymbol] = function () {
    return this;
  };

  var getProto = Object.getPrototypeOf;
  var NativeIteratorPrototype = getProto && getProto(getProto(values([])));
  if (NativeIteratorPrototype &&
      NativeIteratorPrototype !== Op &&
      hasOwn.call(NativeIteratorPrototype, iteratorSymbol)) {
    // This environment has a native %IteratorPrototype%; use it instead
    // of the polyfill.
    IteratorPrototype = NativeIteratorPrototype;
  }

  var Gp = GeneratorFunctionPrototype.prototype =
    Generator.prototype = Object.create(IteratorPrototype);
  GeneratorFunction.prototype = Gp.constructor = GeneratorFunctionPrototype;
  GeneratorFunctionPrototype.constructor = GeneratorFunction;
  GeneratorFunctionPrototype[toStringTagSymbol] =
    GeneratorFunction.displayName = "GeneratorFunction";

  // Helper for defining the .next, .throw, and .return methods of the
  // Iterator interface in terms of a single ._invoke method.
  function defineIteratorMethods(prototype) {
    ["next", "throw", "return"].forEach(function(method) {
      prototype[method] = function(arg) {
        return this._invoke(method, arg);
      };
    });
  }

  runtime.isGeneratorFunction = function(genFun) {
    var ctor = typeof genFun === "function" && genFun.constructor;
    return ctor
      ? ctor === GeneratorFunction ||
        // For the native GeneratorFunction constructor, the best we can
        // do is to check its .name property.
        (ctor.displayName || ctor.name) === "GeneratorFunction"
      : false;
  };

  runtime.mark = function(genFun) {
    if (Object.setPrototypeOf) {
      Object.setPrototypeOf(genFun, GeneratorFunctionPrototype);
    } else {
      genFun.__proto__ = GeneratorFunctionPrototype;
      if (!(toStringTagSymbol in genFun)) {
        genFun[toStringTagSymbol] = "GeneratorFunction";
      }
    }
    genFun.prototype = Object.create(Gp);
    return genFun;
  };

  // Within the body of any async function, `await x` is transformed to
  // `yield regeneratorRuntime.awrap(x)`, so that the runtime can test
  // `hasOwn.call(value, "__await")` to determine if the yielded value is
  // meant to be awaited.
  runtime.awrap = function(arg) {
    return { __await: arg };
  };

  function AsyncIterator(generator) {
    function invoke(method, arg, resolve, reject) {
      var record = tryCatch(generator[method], generator, arg);
      if (record.type === "throw") {
        reject(record.arg);
      } else {
        var result = record.arg;
        var value = result.value;
        if (value &&
            typeof value === "object" &&
            hasOwn.call(value, "__await")) {
          return Promise.resolve(value.__await).then(function(value) {
            invoke("next", value, resolve, reject);
          }, function(err) {
            invoke("throw", err, resolve, reject);
          });
        }

        return Promise.resolve(value).then(function(unwrapped) {
          // When a yielded Promise is resolved, its final value becomes
          // the .value of the Promise<{value,done}> result for the
          // current iteration. If the Promise is rejected, however, the
          // result for this iteration will be rejected with the same
          // reason. Note that rejections of yielded Promises are not
          // thrown back into the generator function, as is the case
          // when an awaited Promise is rejected. This difference in
          // behavior between yield and await is important, because it
          // allows the consumer to decide what to do with the yielded
          // rejection (swallow it and continue, manually .throw it back
          // into the generator, abandon iteration, whatever). With
          // await, by contrast, there is no opportunity to examine the
          // rejection reason outside the generator function, so the
          // only option is to throw it from the await expression, and
          // let the generator function handle the exception.
          result.value = unwrapped;
          resolve(result);
        }, reject);
      }
    }

    var previousPromise;

    function enqueue(method, arg) {
      function callInvokeWithMethodAndArg() {
        return new Promise(function(resolve, reject) {
          invoke(method, arg, resolve, reject);
        });
      }

      return previousPromise =
        // If enqueue has been called before, then we want to wait until
        // all previous Promises have been resolved before calling invoke,
        // so that results are always delivered in the correct order. If
        // enqueue has not been called before, then it is important to
        // call invoke immediately, without waiting on a callback to fire,
        // so that the async generator function has the opportunity to do
        // any necessary setup in a predictable way. This predictability
        // is why the Promise constructor synchronously invokes its
        // executor callback, and why async functions synchronously
        // execute code before the first await. Since we implement simple
        // async functions in terms of async generators, it is especially
        // important to get this right, even though it requires care.
        previousPromise ? previousPromise.then(
          callInvokeWithMethodAndArg,
          // Avoid propagating failures to Promises returned by later
          // invocations of the iterator.
          callInvokeWithMethodAndArg
        ) : callInvokeWithMethodAndArg();
    }

    // Define the unified helper method that is used to implement .next,
    // .throw, and .return (see defineIteratorMethods).
    this._invoke = enqueue;
  }

  defineIteratorMethods(AsyncIterator.prototype);
  AsyncIterator.prototype[asyncIteratorSymbol] = function () {
    return this;
  };
  runtime.AsyncIterator = AsyncIterator;

  // Note that simple async functions are implemented on top of
  // AsyncIterator objects; they just return a Promise for the value of
  // the final result produced by the iterator.
  runtime.async = function(innerFn, outerFn, self, tryLocsList) {
    var iter = new AsyncIterator(
      wrap(innerFn, outerFn, self, tryLocsList)
    );

    return runtime.isGeneratorFunction(outerFn)
      ? iter // If outerFn is a generator, return the full iterator.
      : iter.next().then(function(result) {
          return result.done ? result.value : iter.next();
        });
  };

  function makeInvokeMethod(innerFn, self, context) {
    var state = GenStateSuspendedStart;

    return function invoke(method, arg) {
      if (state === GenStateExecuting) {
        throw new Error("Generator is already running");
      }

      if (state === GenStateCompleted) {
        if (method === "throw") {
          throw arg;
        }

        // Be forgiving, per 25.3.3.3.3 of the spec:
        // https://people.mozilla.org/~jorendorff/es6-draft.html#sec-generatorresume
        return doneResult();
      }

      context.method = method;
      context.arg = arg;

      while (true) {
        var delegate = context.delegate;
        if (delegate) {
          var delegateResult = maybeInvokeDelegate(delegate, context);
          if (delegateResult) {
            if (delegateResult === ContinueSentinel) continue;
            return delegateResult;
          }
        }

        if (context.method === "next") {
          // Setting context._sent for legacy support of Babel's
          // function.sent implementation.
          context.sent = context._sent = context.arg;

        } else if (context.method === "throw") {
          if (state === GenStateSuspendedStart) {
            state = GenStateCompleted;
            throw context.arg;
          }

          context.dispatchException(context.arg);

        } else if (context.method === "return") {
          context.abrupt("return", context.arg);
        }

        state = GenStateExecuting;

        var record = tryCatch(innerFn, self, context);
        if (record.type === "normal") {
          // If an exception is thrown from innerFn, we leave state ===
          // GenStateExecuting and loop back for another invocation.
          state = context.done
            ? GenStateCompleted
            : GenStateSuspendedYield;

          if (record.arg === ContinueSentinel) {
            continue;
          }

          return {
            value: record.arg,
            done: context.done
          };

        } else if (record.type === "throw") {
          state = GenStateCompleted;
          // Dispatch the exception by looping back around to the
          // context.dispatchException(context.arg) call above.
          context.method = "throw";
          context.arg = record.arg;
        }
      }
    };
  }

  // Call delegate.iterator[context.method](context.arg) and handle the
  // result, either by returning a { value, done } result from the
  // delegate iterator, or by modifying context.method and context.arg,
  // setting context.delegate to null, and returning the ContinueSentinel.
  function maybeInvokeDelegate(delegate, context) {
    var method = delegate.iterator[context.method];
    if (method === undefined) {
      // A .throw or .return when the delegate iterator has no .throw
      // method always terminates the yield* loop.
      context.delegate = null;

      if (context.method === "throw") {
        if (delegate.iterator.return) {
          // If the delegate iterator has a return method, give it a
          // chance to clean up.
          context.method = "return";
          context.arg = undefined;
          maybeInvokeDelegate(delegate, context);

          if (context.method === "throw") {
            // If maybeInvokeDelegate(context) changed context.method from
            // "return" to "throw", let that override the TypeError below.
            return ContinueSentinel;
          }
        }

        context.method = "throw";
        context.arg = new TypeError(
          "The iterator does not provide a 'throw' method");
      }

      return ContinueSentinel;
    }

    var record = tryCatch(method, delegate.iterator, context.arg);

    if (record.type === "throw") {
      context.method = "throw";
      context.arg = record.arg;
      context.delegate = null;
      return ContinueSentinel;
    }

    var info = record.arg;

    if (! info) {
      context.method = "throw";
      context.arg = new TypeError("iterator result is not an object");
      context.delegate = null;
      return ContinueSentinel;
    }

    if (info.done) {
      // Assign the result of the finished delegate to the temporary
      // variable specified by delegate.resultName (see delegateYield).
      context[delegate.resultName] = info.value;

      // Resume execution at the desired location (see delegateYield).
      context.next = delegate.nextLoc;

      // If context.method was "throw" but the delegate handled the
      // exception, let the outer generator proceed normally. If
      // context.method was "next", forget context.arg since it has been
      // "consumed" by the delegate iterator. If context.method was
      // "return", allow the original .return call to continue in the
      // outer generator.
      if (context.method !== "return") {
        context.method = "next";
        context.arg = undefined;
      }

    } else {
      // Re-yield the result returned by the delegate method.
      return info;
    }

    // The delegate iterator is finished, so forget it and continue with
    // the outer generator.
    context.delegate = null;
    return ContinueSentinel;
  }

  // Define Generator.prototype.{next,throw,return} in terms of the
  // unified ._invoke helper method.
  defineIteratorMethods(Gp);

  Gp[toStringTagSymbol] = "Generator";

  // A Generator should always return itself as the iterator object when the
  // @@iterator function is called on it. Some browsers' implementations of the
  // iterator prototype chain incorrectly implement this, causing the Generator
  // object to not be returned from this call. This ensures that doesn't happen.
  // See https://github.com/facebook/regenerator/issues/274 for more details.
  Gp[iteratorSymbol] = function() {
    return this;
  };

  Gp.toString = function() {
    return "[object Generator]";
  };

  function pushTryEntry(locs) {
    var entry = { tryLoc: locs[0] };

    if (1 in locs) {
      entry.catchLoc = locs[1];
    }

    if (2 in locs) {
      entry.finallyLoc = locs[2];
      entry.afterLoc = locs[3];
    }

    this.tryEntries.push(entry);
  }

  function resetTryEntry(entry) {
    var record = entry.completion || {};
    record.type = "normal";
    delete record.arg;
    entry.completion = record;
  }

  function Context(tryLocsList) {
    // The root entry object (effectively a try statement without a catch
    // or a finally block) gives us a place to store values thrown from
    // locations where there is no enclosing try statement.
    this.tryEntries = [{ tryLoc: "root" }];
    tryLocsList.forEach(pushTryEntry, this);
    this.reset(true);
  }

  runtime.keys = function(object) {
    var keys = [];
    for (var key in object) {
      keys.push(key);
    }
    keys.reverse();

    // Rather than returning an object with a next method, we keep
    // things simple and return the next function itself.
    return function next() {
      while (keys.length) {
        var key = keys.pop();
        if (key in object) {
          next.value = key;
          next.done = false;
          return next;
        }
      }

      // To avoid creating an additional object, we just hang the .value
      // and .done properties off the next function object itself. This
      // also ensures that the minifier will not anonymize the function.
      next.done = true;
      return next;
    };
  };

  function values(iterable) {
    if (iterable) {
      var iteratorMethod = iterable[iteratorSymbol];
      if (iteratorMethod) {
        return iteratorMethod.call(iterable);
      }

      if (typeof iterable.next === "function") {
        return iterable;
      }

      if (!isNaN(iterable.length)) {
        var i = -1, next = function next() {
          while (++i < iterable.length) {
            if (hasOwn.call(iterable, i)) {
              next.value = iterable[i];
              next.done = false;
              return next;
            }
          }

          next.value = undefined;
          next.done = true;

          return next;
        };

        return next.next = next;
      }
    }

    // Return an iterator with no values.
    return { next: doneResult };
  }
  runtime.values = values;

  function doneResult() {
    return { value: undefined, done: true };
  }

  Context.prototype = {
    constructor: Context,

    reset: function(skipTempReset) {
      this.prev = 0;
      this.next = 0;
      // Resetting context._sent for legacy support of Babel's
      // function.sent implementation.
      this.sent = this._sent = undefined;
      this.done = false;
      this.delegate = null;

      this.method = "next";
      this.arg = undefined;

      this.tryEntries.forEach(resetTryEntry);

      if (!skipTempReset) {
        for (var name in this) {
          // Not sure about the optimal order of these conditions:
          if (name.charAt(0) === "t" &&
              hasOwn.call(this, name) &&
              !isNaN(+name.slice(1))) {
            this[name] = undefined;
          }
        }
      }
    },

    stop: function() {
      this.done = true;

      var rootEntry = this.tryEntries[0];
      var rootRecord = rootEntry.completion;
      if (rootRecord.type === "throw") {
        throw rootRecord.arg;
      }

      return this.rval;
    },

    dispatchException: function(exception) {
      if (this.done) {
        throw exception;
      }

      var context = this;
      function handle(loc, caught) {
        record.type = "throw";
        record.arg = exception;
        context.next = loc;

        if (caught) {
          // If the dispatched exception was caught by a catch block,
          // then let that catch block handle the exception normally.
          context.method = "next";
          context.arg = undefined;
        }

        return !! caught;
      }

      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        var record = entry.completion;

        if (entry.tryLoc === "root") {
          // Exception thrown outside of any try block that could handle
          // it, so set the completion value of the entire function to
          // throw the exception.
          return handle("end");
        }

        if (entry.tryLoc <= this.prev) {
          var hasCatch = hasOwn.call(entry, "catchLoc");
          var hasFinally = hasOwn.call(entry, "finallyLoc");

          if (hasCatch && hasFinally) {
            if (this.prev < entry.catchLoc) {
              return handle(entry.catchLoc, true);
            } else if (this.prev < entry.finallyLoc) {
              return handle(entry.finallyLoc);
            }

          } else if (hasCatch) {
            if (this.prev < entry.catchLoc) {
              return handle(entry.catchLoc, true);
            }

          } else if (hasFinally) {
            if (this.prev < entry.finallyLoc) {
              return handle(entry.finallyLoc);
            }

          } else {
            throw new Error("try statement without catch or finally");
          }
        }
      }
    },

    abrupt: function(type, arg) {
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        if (entry.tryLoc <= this.prev &&
            hasOwn.call(entry, "finallyLoc") &&
            this.prev < entry.finallyLoc) {
          var finallyEntry = entry;
          break;
        }
      }

      if (finallyEntry &&
          (type === "break" ||
           type === "continue") &&
          finallyEntry.tryLoc <= arg &&
          arg <= finallyEntry.finallyLoc) {
        // Ignore the finally entry if control is not jumping to a
        // location outside the try/catch block.
        finallyEntry = null;
      }

      var record = finallyEntry ? finallyEntry.completion : {};
      record.type = type;
      record.arg = arg;

      if (finallyEntry) {
        this.method = "next";
        this.next = finallyEntry.finallyLoc;
        return ContinueSentinel;
      }

      return this.complete(record);
    },

    complete: function(record, afterLoc) {
      if (record.type === "throw") {
        throw record.arg;
      }

      if (record.type === "break" ||
          record.type === "continue") {
        this.next = record.arg;
      } else if (record.type === "return") {
        this.rval = this.arg = record.arg;
        this.method = "return";
        this.next = "end";
      } else if (record.type === "normal" && afterLoc) {
        this.next = afterLoc;
      }

      return ContinueSentinel;
    },

    finish: function(finallyLoc) {
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        if (entry.finallyLoc === finallyLoc) {
          this.complete(entry.completion, entry.afterLoc);
          resetTryEntry(entry);
          return ContinueSentinel;
        }
      }
    },

    "catch": function(tryLoc) {
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        if (entry.tryLoc === tryLoc) {
          var record = entry.completion;
          if (record.type === "throw") {
            var thrown = record.arg;
            resetTryEntry(entry);
          }
          return thrown;
        }
      }

      // The context.catch method must only be called with a location
      // argument that corresponds to a known catch block.
      throw new Error("illegal catch attempt");
    },

    delegateYield: function(iterable, resultName, nextLoc) {
      this.delegate = {
        iterator: values(iterable),
        resultName: resultName,
        nextLoc: nextLoc
      };

      if (this.method === "next") {
        // Deliberately forget the last sent value so that we don't
        // accidentally pass it on to the delegate.
        this.arg = undefined;
      }

      return ContinueSentinel;
    }
  };
})(
  // In sloppy mode, unbound `this` refers to the global object, fallback to
  // Function constructor if we're in global strict mode. That is sadly a form
  // of indirect eval which violates Content Security Policy.
  (function() { return this })() || Function("return this")()
);

},{}],127:[function(require,module,exports){
var Emitter = require('component-emitter');

var SCChannel = function (name, client, options) {
  var self = this;

  Emitter.call(this);

  this.PENDING = 'pending';
  this.SUBSCRIBED = 'subscribed';
  this.UNSUBSCRIBED = 'unsubscribed';

  this.name = name;
  this.state = this.UNSUBSCRIBED;
  this.client = client;

  this.options = options || {};
  this.setOptions(this.options);
};

SCChannel.prototype = Object.create(Emitter.prototype);

SCChannel.prototype.setOptions = function (options) {
  if (!options) {
    options = {};
  }
  this.waitForAuth = options.waitForAuth || false;
  this.batch = options.batch || false;

  if (options.data !== undefined) {
    this.data = options.data;
  }
};

SCChannel.prototype.getState = function () {
  return this.state;
};

SCChannel.prototype.subscribe = function (options) {
  this.client.subscribe(this.name, options);
};

SCChannel.prototype.unsubscribe = function () {
  this.client.unsubscribe(this.name);
};

SCChannel.prototype.isSubscribed = function (includePending) {
  return this.client.isSubscribed(this.name, includePending);
};

SCChannel.prototype.publish = function (data, callback) {
  this.client.publish(this.name, data, callback);
};

SCChannel.prototype.watch = function (handler) {
  this.client.watch(this.name, handler);
};

SCChannel.prototype.unwatch = function (handler) {
  this.client.unwatch(this.name, handler);
};

SCChannel.prototype.watchers = function () {
  return this.client.watchers(this.name);
};

SCChannel.prototype.destroy = function () {
  this.client.destroyChannel(this.name);
};

module.exports.SCChannel = SCChannel;

},{"component-emitter":19}],128:[function(require,module,exports){
// Based on https://github.com/dscape/cycle/blob/master/cycle.js

module.exports = function decycle(object) {
// Make a deep copy of an object or array, assuring that there is at most
// one instance of each object or array in the resulting structure. The
// duplicate references (which might be forming cycles) are replaced with
// an object of the form
//      {$ref: PATH}
// where the PATH is a JSONPath string that locates the first occurance.
// So,
//      var a = [];
//      a[0] = a;
//      return JSON.stringify(JSON.decycle(a));
// produces the string '[{"$ref":"$"}]'.

// JSONPath is used to locate the unique object. $ indicates the top level of
// the object or array. [NUMBER] or [STRING] indicates a child member or
// property.

    var objects = [],   // Keep a reference to each unique object or array
        paths = [];     // Keep the path to each unique object or array

    return (function derez(value, path) {

// The derez recurses through the object, producing the deep copy.

        var i,          // The loop counter
            name,       // Property name
            nu;         // The new object or array

// typeof null === 'object', so go on if this value is really an object but not
// one of the weird builtin objects.

        if (typeof value === 'object' && value !== null &&
                !(value instanceof Boolean) &&
                !(value instanceof Date)    &&
                !(value instanceof Number)  &&
                !(value instanceof RegExp)  &&
                !(value instanceof String)) {

// If the value is an object or array, look to see if we have already
// encountered it. If so, return a $ref/path object. This is a hard way,
// linear search that will get slower as the number of unique objects grows.

            for (i = 0; i < objects.length; i += 1) {
                if (objects[i] === value) {
                    return {$ref: paths[i]};
                }
            }

// Otherwise, accumulate the unique value and its path.

            objects.push(value);
            paths.push(path);

// If it is an array, replicate the array.

            if (Object.prototype.toString.apply(value) === '[object Array]') {
                nu = [];
                for (i = 0; i < value.length; i += 1) {
                    nu[i] = derez(value[i], path + '[' + i + ']');
                }
            } else {

// If it is an object, replicate the object.

                nu = {};
                for (name in value) {
                    if (Object.prototype.hasOwnProperty.call(value, name)) {
                        nu[name] = derez(value[name],
                            path + '[' + JSON.stringify(name) + ']');
                    }
                }
            }
            return nu;
        }
        return value;
    }(object, '$'));
};

},{}],129:[function(require,module,exports){
var decycle = require('./decycle');

var isStrict = (function () { return !this; })();

function AuthTokenExpiredError(message, expiry) {
  this.name = 'AuthTokenExpiredError';
  this.message = message;
  this.expiry = expiry;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
AuthTokenExpiredError.prototype = Object.create(Error.prototype);


function AuthTokenInvalidError(message) {
  this.name = 'AuthTokenInvalidError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
AuthTokenInvalidError.prototype = Object.create(Error.prototype);


function AuthTokenNotBeforeError(message, date) {
  this.name = 'AuthTokenNotBeforeError';
  this.message = message;
  this.date = date;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
AuthTokenNotBeforeError.prototype = Object.create(Error.prototype);


// For any other auth token error.
function AuthTokenError(message) {
  this.name = 'AuthTokenError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
AuthTokenError.prototype = Object.create(Error.prototype);


function SilentMiddlewareBlockedError(message, type) {
  this.name = 'SilentMiddlewareBlockedError';
  this.message = message;
  this.type = type;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
SilentMiddlewareBlockedError.prototype = Object.create(Error.prototype);


function InvalidActionError(message) {
  this.name = 'InvalidActionError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
InvalidActionError.prototype = Object.create(Error.prototype);

function InvalidArgumentsError(message) {
  this.name = 'InvalidArgumentsError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
InvalidArgumentsError.prototype = Object.create(Error.prototype);

function InvalidOptionsError(message) {
  this.name = 'InvalidOptionsError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
InvalidOptionsError.prototype = Object.create(Error.prototype);


function InvalidMessageError(message) {
  this.name = 'InvalidMessageError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
InvalidMessageError.prototype = Object.create(Error.prototype);


function SocketProtocolError(message, code) {
  this.name = 'SocketProtocolError';
  this.message = message;
  this.code = code;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
SocketProtocolError.prototype = Object.create(Error.prototype);


function ServerProtocolError(message) {
  this.name = 'ServerProtocolError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
ServerProtocolError.prototype = Object.create(Error.prototype);

function HTTPServerError(message) {
  this.name = 'HTTPServerError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
HTTPServerError.prototype = Object.create(Error.prototype);


function ResourceLimitError(message) {
  this.name = 'ResourceLimitError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
ResourceLimitError.prototype = Object.create(Error.prototype);


function TimeoutError(message) {
  this.name = 'TimeoutError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
TimeoutError.prototype = Object.create(Error.prototype);


function BadConnectionError(message, type) {
  this.name = 'BadConnectionError';
  this.message = message;
  this.type = type;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
BadConnectionError.prototype = Object.create(Error.prototype);


function BrokerError(message) {
  this.name = 'BrokerError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
BrokerError.prototype = Object.create(Error.prototype);


function ProcessExitError(message, code) {
  this.name = 'ProcessExitError';
  this.message = message;
  this.code = code;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
ProcessExitError.prototype = Object.create(Error.prototype);


function UnknownError(message) {
  this.name = 'UnknownError';
  this.message = message;
  if (Error.captureStackTrace && !isStrict) {
    Error.captureStackTrace(this, arguments.callee);
  } else {
    this.stack = (new Error()).stack;
  }
}
UnknownError.prototype = Object.create(Error.prototype);


// Expose all error types.

module.exports = {
  AuthTokenExpiredError: AuthTokenExpiredError,
  AuthTokenInvalidError: AuthTokenInvalidError,
  AuthTokenNotBeforeError: AuthTokenNotBeforeError,
  AuthTokenError: AuthTokenError,
  SilentMiddlewareBlockedError: SilentMiddlewareBlockedError,
  InvalidActionError: InvalidActionError,
  InvalidArgumentsError: InvalidArgumentsError,
  InvalidOptionsError: InvalidOptionsError,
  InvalidMessageError: InvalidMessageError,
  SocketProtocolError: SocketProtocolError,
  ServerProtocolError: ServerProtocolError,
  HTTPServerError: HTTPServerError,
  ResourceLimitError: ResourceLimitError,
  TimeoutError: TimeoutError,
  BadConnectionError: BadConnectionError,
  BrokerError: BrokerError,
  ProcessExitError: ProcessExitError,
  UnknownError: UnknownError
};

module.exports.socketProtocolErrorStatuses = {
  1001: 'Socket was disconnected',
  1002: 'A WebSocket protocol error was encountered',
  1003: 'Server terminated socket because it received invalid data',
  1005: 'Socket closed without status code',
  1006: 'Socket hung up',
  1007: 'Message format was incorrect',
  1008: 'Encountered a policy violation',
  1009: 'Message was too big to process',
  1010: 'Client ended the connection because the server did not comply with extension requirements',
  1011: 'Server encountered an unexpected fatal condition',
  4000: 'Server ping timed out',
  4001: 'Client pong timed out',
  4002: 'Server failed to sign auth token',
  4003: 'Failed to complete handshake',
  4004: 'Client failed to save auth token',
  4005: 'Did not receive #handshake from client before timeout',
  4006: 'Failed to bind socket to message broker',
  4007: 'Client connection establishment timed out',
  4008: 'Server rejected handshake from client'
};

module.exports.socketProtocolIgnoreStatuses = {
  1000: 'Socket closed normally',
  1001: 'Socket hung up'
};

// Properties related to error domains cannot be serialized.
var unserializableErrorProperties = {
  domain: 1,
  domainEmitter: 1,
  domainThrown: 1
};

// Convert an error into a JSON-compatible type which can later be hydrated
// back to its *original* form.
module.exports.dehydrateError = function dehydrateError(error, includeStackTrace) {
  var dehydratedError;

  if (error && typeof error === 'object') {
    dehydratedError = {
      message: error.message
    };
    if (includeStackTrace) {
      dehydratedError.stack = error.stack;
    }
    for (var i in error) {
      if (!unserializableErrorProperties[i]) {
        dehydratedError[i] = error[i];
      }
    }
  } else if (typeof error === 'function') {
    dehydratedError = '[function ' + (error.name || 'anonymous') + ']';
  } else {
    dehydratedError = error;
  }

  return decycle(dehydratedError);
};

// Convert a dehydrated error back to its *original* form.
module.exports.hydrateError = function hydrateError(error) {
  var hydratedError = null;
  if (error != null) {
    if (typeof error === 'object') {
      hydratedError = new Error(error.message);
      for (var i in error) {
        if (error.hasOwnProperty(i)) {
          hydratedError[i] = error[i];
        }
      }
    } else {
      hydratedError = error;
    }
  }
  return hydratedError;
};

module.exports.decycle = decycle;

},{"./decycle":128}],130:[function(require,module,exports){
(function (global){
var base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var validJSONStartRegex = /^[ \n\r\t]*[{\[]/;

var arrayBufferToBase64 = function (arraybuffer) {
  var bytes = new Uint8Array(arraybuffer);
  var len = bytes.length;
  var base64 = '';

  for (var i = 0; i < len; i += 3) {
    base64 += base64Chars[bytes[i] >> 2];
    base64 += base64Chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
    base64 += base64Chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
    base64 += base64Chars[bytes[i + 2] & 63];
  }

  if ((len % 3) === 2) {
    base64 = base64.substring(0, base64.length - 1) + '=';
  } else if (len % 3 === 1) {
    base64 = base64.substring(0, base64.length - 2) + '==';
  }

  return base64;
};

var binaryToBase64Replacer = function (key, value) {
  if (global.ArrayBuffer && value instanceof global.ArrayBuffer) {
    return {
      base64: true,
      data: arrayBufferToBase64(value)
    };
  } else if (global.Buffer) {
    if (value instanceof global.Buffer){
      return {
        base64: true,
        data: value.toString('base64')
      };
    }
    // Some versions of Node.js convert Buffers to Objects before they are passed to
    // the replacer function - Because of this, we need to rehydrate Buffers
    // before we can convert them to base64 strings.
    if (value && value.type === 'Buffer' && Array.isArray(value.data)) {
      var rehydratedBuffer;
      if (global.Buffer.from) {
        rehydratedBuffer = global.Buffer.from(value.data);
      } else {
        rehydratedBuffer = new global.Buffer(value.data);
      }
      return {
        base64: true,
        data: rehydratedBuffer.toString('base64')
      };
    }
  }
  return value;
};

// Decode the data which was transmitted over the wire to a JavaScript Object in a format which SC understands.
// See encode function below for more details.
module.exports.decode = function (input) {
  if (input == null) {
   return null;
  }
  // Leave ping or pong message as is
  if (input === '#1' || input === '#2') {
    return input;
  }
  var message = input.toString();

  // Performance optimization to detect invalid JSON packet sooner.
  if (!validJSONStartRegex.test(message)) {
    return message;
  }

  try {
    return JSON.parse(message);
  } catch (err) {}
  return message;
};

// Encode a raw JavaScript object (which is in the SC protocol format) into a format for
// transfering it over the wire. In this case, we just convert it into a simple JSON string.
// If you want to create your own custom codec, you can encode the object into any format
// (e.g. binary ArrayBuffer or string with any kind of compression) so long as your decode
// function is able to rehydrate that object back into its original JavaScript Object format
// (which adheres to the SC protocol).
// See https://github.com/SocketCluster/socketcluster/blob/master/socketcluster-protocol.md
// for details about the SC protocol.
module.exports.encode = function (object) {
  // Leave ping or pong message as is
  if (object === '#1' || object === '#2') {
    return object;
  }
  return JSON.stringify(object, binaryToBase64Replacer);
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],131:[function(require,module,exports){
var SCClientSocket = require('./lib/scclientsocket');
var factory = require('./lib/factory');

module.exports.factory = factory;
module.exports.SCClientSocket = SCClientSocket;

module.exports.Emitter = require('component-emitter');

module.exports.create = function (options) {
  return factory.create(options);
};

module.exports.connect = module.exports.create;

module.exports.destroy = function (socket) {
  return factory.destroy(socket);
};

module.exports.clients = factory.clients;

module.exports.version = '14.2.1';

},{"./lib/factory":133,"./lib/scclientsocket":135,"component-emitter":19}],132:[function(require,module,exports){
(function (global){
var AuthEngine = function () {
  this._internalStorage = {};
  this.isLocalStorageEnabled = this._checkLocalStorageEnabled();
};

AuthEngine.prototype._checkLocalStorageEnabled = function () {
  var err;
  try {
    // Some browsers will throw an error here if localStorage is disabled.
    global.localStorage;

    // Safari, in Private Browsing Mode, looks like it supports localStorage but all calls to setItem
    // throw QuotaExceededError. We're going to detect this and avoid hard to debug edge cases.
    global.localStorage.setItem('__scLocalStorageTest', 1);
    global.localStorage.removeItem('__scLocalStorageTest');
  } catch (e) {
    err = e;
  }
  return !err;
};

AuthEngine.prototype.saveToken = function (name, token, options, callback) {
  if (this.isLocalStorageEnabled && global.localStorage) {
    global.localStorage.setItem(name, token);
  } else {
    this._internalStorage[name] = token;
  }
  callback && callback(null, token);
};

AuthEngine.prototype.removeToken = function (name, callback) {
  var token;

  this.loadToken(name, function (err, authToken) {
    token = authToken;
  });

  if (this.isLocalStorageEnabled && global.localStorage) {
    global.localStorage.removeItem(name);
  } else {
    delete this._internalStorage[name];
  }

  callback && callback(null, token);
};

AuthEngine.prototype.loadToken = function (name, callback) {
  var token;

  if (this.isLocalStorageEnabled && global.localStorage) {
    token = global.localStorage.getItem(name);
  } else {
    token = this._internalStorage[name] || null;
  }
  callback(null, token);
};

module.exports.AuthEngine = AuthEngine;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],133:[function(require,module,exports){
(function (global){
var SCClientSocket = require('./scclientsocket');
var scErrors = require('sc-errors');
var uuid = require('uuid');
var InvalidArgumentsError = scErrors.InvalidArgumentsError;

var _clients = {};

function getMultiplexId(options) {
  var protocolPrefix = options.secure ? 'https://' : 'http://';
  var queryString = '';
  if (options.query) {
    if (typeof options.query === 'string') {
      queryString = options.query;
    } else {
      var queryArray = [];
      var queryMap = options.query;
      for (var key in queryMap) {
        if (queryMap.hasOwnProperty(key)) {
          queryArray.push(key + '=' + queryMap[key]);
        }
      }
      if (queryArray.length) {
        queryString = '?' + queryArray.join('&');
      }
    }
  }
  var host;
  if (options.host) {
    host = options.host;
  } else {
    host = options.hostname + ':' + options.port;
  }
  return protocolPrefix + host + options.path + queryString;
}

function isUrlSecure() {
  return global.location && location.protocol === 'https:';
}

function getPort(options, isSecureDefault) {
  var isSecure = options.secure == null ? isSecureDefault : options.secure;
  return options.port || (global.location && location.port ? location.port : isSecure ? 443 : 80);
}

function create(options) {
  var self = this;

  options = options || {};

  if (options.host && !options.host.match(/[^:]+:\d{2,5}/)) {
    throw new InvalidArgumentsError('The host option should include both' +
      ' the hostname and the port number in the format "hostname:port"');
  }

  if (options.host && options.hostname) {
    throw new InvalidArgumentsError('The host option should already include' +
      ' the hostname and the port number in the format "hostname:port"' +
      ' - Because of this, you should never use host and hostname options together');
  }

  if (options.host && options.port) {
    throw new InvalidArgumentsError('The host option should already include' +
      ' the hostname and the port number in the format "hostname:port"' +
      ' - Because of this, you should never use host and port options together');
  }

  var isSecureDefault = isUrlSecure();

  var opts = {
    port: getPort(options, isSecureDefault),
    hostname: global.location && location.hostname || 'localhost',
    path: '/socketcluster/',
    secure: isSecureDefault,
    autoConnect: true,
    autoReconnect: true,
    autoSubscribeOnConnect: true,
    connectTimeout: 20000,
    ackTimeout: 10000,
    timestampRequests: false,
    timestampParam: 't',
    authEngine: null,
    authTokenName: 'socketCluster.authToken',
    binaryType: 'arraybuffer',
    multiplex: true,
    pubSubBatchDuration: null,
    cloneData: false
  };
  for (var i in options) {
    if (options.hasOwnProperty(i)) {
      opts[i] = options[i];
    }
  }
  opts.clientMap = _clients;

  if (opts.multiplex === false) {
    opts.clientId = uuid.v4();
    var socket = new SCClientSocket(opts);
    _clients[opts.clientId] = socket;
    return socket;
  }
  opts.clientId = getMultiplexId(opts);

  if (_clients[opts.clientId]) {
    if (opts.autoConnect) {
      _clients[opts.clientId].connect();
    }
  } else {
    _clients[opts.clientId] = new SCClientSocket(opts);
  }
  return _clients[opts.clientId];
}

function destroy(socket) {
  socket.destroy();
}

module.exports = {
  create: create,
  destroy: destroy,
  clients: _clients
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./scclientsocket":135,"sc-errors":129,"uuid":138}],134:[function(require,module,exports){
var scErrors = require('sc-errors');
var InvalidActionError = scErrors.InvalidActionError;

var Response = function (socket, id) {
  this.socket = socket;
  this.id = id;
  this.sent = false;
};

Response.prototype._respond = function (responseData) {
  if (this.sent) {
    throw new InvalidActionError('Response ' + this.id + ' has already been sent');
  } else {
    this.sent = true;
    this.socket.send(this.socket.encode(responseData));
  }
};

Response.prototype.end = function (data) {
  if (this.id) {
    var responseData = {
      rid: this.id
    };
    if (data !== undefined) {
      responseData.data = data;
    }
    this._respond(responseData);
  }
};

Response.prototype.error = function (error, data) {
  if (this.id) {
    var err = scErrors.dehydrateError(error);

    var responseData = {
      rid: this.id,
      error: err
    };
    if (data !== undefined) {
      responseData.data = data;
    }

    this._respond(responseData);
  }
};

Response.prototype.callback = function (error, data) {
  if (error) {
    this.error(error, data);
  } else {
    this.end(data);
  }
};

module.exports.Response = Response;

},{"sc-errors":129}],135:[function(require,module,exports){
(function (global,Buffer){
var Emitter = require('component-emitter');
var SCChannel = require('sc-channel').SCChannel;
var Response = require('./response').Response;
var AuthEngine = require('./auth').AuthEngine;
var formatter = require('sc-formatter');
var SCTransport = require('./sctransport').SCTransport;
var querystring = require('querystring');
var LinkedList = require('linked-list');
var base64 = require('base-64');
var clone = require('clone');

var scErrors = require('sc-errors');
var InvalidArgumentsError = scErrors.InvalidArgumentsError;
var InvalidMessageError = scErrors.InvalidMessageError;
var InvalidActionError = scErrors.InvalidActionError;
var SocketProtocolError = scErrors.SocketProtocolError;
var TimeoutError = scErrors.TimeoutError;
var BadConnectionError = scErrors.BadConnectionError;

var isBrowser = typeof window !== 'undefined';


var SCClientSocket = function (opts) {
  var self = this;

  Emitter.call(this);

  this.id = null;
  this.state = this.CLOSED;
  this.authState = this.UNAUTHENTICATED;
  this.signedAuthToken = null;
  this.authToken = null;
  this.pendingReconnect = false;
  this.pendingReconnectTimeout = null;
  this.preparingPendingSubscriptions = false;
  this.clientId = opts.clientId;

  this.connectTimeout = opts.connectTimeout;
  this.ackTimeout = opts.ackTimeout;
  this.channelPrefix = opts.channelPrefix || null;
  this.disconnectOnUnload = opts.disconnectOnUnload == null ? true : opts.disconnectOnUnload;
  this.authTokenName = opts.authTokenName;

  // pingTimeout will be ackTimeout at the start, but it will
  // be updated with values provided by the 'connect' event
  this.pingTimeout = this.ackTimeout;
  this.pingTimeoutDisabled = !!opts.pingTimeoutDisabled;
  this.active = true;

  this._clientMap = opts.clientMap || {};

  var maxTimeout = Math.pow(2, 31) - 1;

  var verifyDuration = function (propertyName) {
    if (self[propertyName] > maxTimeout) {
      throw new InvalidArgumentsError('The ' + propertyName +
        ' value provided exceeded the maximum amount allowed');
    }
  };

  verifyDuration('connectTimeout');
  verifyDuration('ackTimeout');

  this._localEvents = {
    'connect': 1,
    'connectAbort': 1,
    'close': 1,
    'disconnect': 1,
    'message': 1,
    'error': 1,
    'raw': 1,
    'kickOut': 1,
    'subscribe': 1,
    'unsubscribe': 1,
    'subscribeStateChange': 1,
    'authStateChange': 1,
    'authenticate': 1,
    'deauthenticate': 1,
    'removeAuthToken': 1,
    'subscribeRequest': 1
  };

  this.connectAttempts = 0;

  this._emitBuffer = new LinkedList();
  this.channels = {};

  this.options = opts;

  this._cid = 1;

  this.options.callIdGenerator = function () {
    return self._cid++;
  };

  if (this.options.autoReconnect) {
    if (this.options.autoReconnectOptions == null) {
      this.options.autoReconnectOptions = {};
    }

    // Add properties to the this.options.autoReconnectOptions object.
    // We assign the reference to a reconnectOptions variable to avoid repetition.
    var reconnectOptions = this.options.autoReconnectOptions;
    if (reconnectOptions.initialDelay == null) {
      reconnectOptions.initialDelay = 10000;
    }
    if (reconnectOptions.randomness == null) {
      reconnectOptions.randomness = 10000;
    }
    if (reconnectOptions.multiplier == null) {
      reconnectOptions.multiplier = 1.5;
    }
    if (reconnectOptions.maxDelay == null) {
      reconnectOptions.maxDelay = 60000;
    }
  }

  if (this.options.subscriptionRetryOptions == null) {
    this.options.subscriptionRetryOptions = {};
  }

  if (this.options.authEngine) {
    this.auth = this.options.authEngine;
  } else {
    this.auth = new AuthEngine();
  }

  if (this.options.codecEngine) {
    this.codec = this.options.codecEngine;
  } else {
    // Default codec engine
    this.codec = formatter;
  }

  if (this.options.protocol) {
    var protocolOptionError = new InvalidArgumentsError('The "protocol" option' +
      ' does not affect socketcluster-client. If you want to utilize SSL/TLS' +
      ' - use "secure" option instead');
    this._onSCError(protocolOptionError);
  }

  this.options.path = this.options.path.replace(/\/$/, '') + '/';

  this.options.query = opts.query || {};
  if (typeof this.options.query === 'string') {
    this.options.query = querystring.parse(this.options.query);
  }

  this._channelEmitter = new Emitter();

  this._unloadHandler = function () {
    self.disconnect();
  };

  if (isBrowser && this.disconnectOnUnload && global.addEventListener) {
    global.addEventListener('beforeunload', this._unloadHandler, false);
  }
  this._clientMap[this.clientId] = this;

  if (this.options.autoConnect) {
    this.connect();
  }
};

SCClientSocket.prototype = Object.create(Emitter.prototype);

SCClientSocket.CONNECTING = SCClientSocket.prototype.CONNECTING = SCTransport.prototype.CONNECTING;
SCClientSocket.OPEN = SCClientSocket.prototype.OPEN = SCTransport.prototype.OPEN;
SCClientSocket.CLOSED = SCClientSocket.prototype.CLOSED = SCTransport.prototype.CLOSED;

SCClientSocket.AUTHENTICATED = SCClientSocket.prototype.AUTHENTICATED = 'authenticated';
SCClientSocket.UNAUTHENTICATED = SCClientSocket.prototype.UNAUTHENTICATED = 'unauthenticated';

SCClientSocket.PENDING = SCClientSocket.prototype.PENDING = 'pending';

SCClientSocket.ignoreStatuses = scErrors.socketProtocolIgnoreStatuses;
SCClientSocket.errorStatuses = scErrors.socketProtocolErrorStatuses;

SCClientSocket.prototype._privateEventHandlerMap = {
  '#publish': function (data) {
    var undecoratedChannelName = this._undecorateChannelName(data.channel);
    var isSubscribed = this.isSubscribed(undecoratedChannelName, true);

    if (isSubscribed) {
      this._channelEmitter.emit(undecoratedChannelName, data.data);
    }
  },
  '#kickOut': function (data) {
    var undecoratedChannelName = this._undecorateChannelName(data.channel);
    var channel = this.channels[undecoratedChannelName];
    if (channel) {
      Emitter.prototype.emit.call(this, 'kickOut', data.message, undecoratedChannelName);
      channel.emit('kickOut', data.message, undecoratedChannelName);
      this._triggerChannelUnsubscribe(channel);
    }
  },
  '#setAuthToken': function (data, response) {
    var self = this;

    if (data) {
      var triggerAuthenticate = function (err) {
        if (err) {
          // This is a non-fatal error, we don't want to close the connection
          // because of this but we do want to notify the server and throw an error
          // on the client.
          response.error(err);
          self._onSCError(err);
        } else {
          self._changeToAuthenticatedState(data.token);
          response.end();
        }
      };

      this.auth.saveToken(this.authTokenName, data.token, {}, triggerAuthenticate);
    } else {
      response.error(new InvalidMessageError('No token data provided by #setAuthToken event'));
    }
  },
  '#removeAuthToken': function (data, response) {
    var self = this;

    this.auth.removeToken(this.authTokenName, function (err, oldToken) {
      if (err) {
        // Non-fatal error - Do not close the connection
        response.error(err);
        self._onSCError(err);
      } else {
        Emitter.prototype.emit.call(self, 'removeAuthToken', oldToken);
        self._changeToUnauthenticatedStateAndClearTokens();
        response.end();
      }
    });
  },
  '#disconnect': function (data) {
    this.transport.close(data.code, data.data);
  }
};

SCClientSocket.prototype.getState = function () {
  return this.state;
};

SCClientSocket.prototype.getBytesReceived = function () {
  return this.transport.getBytesReceived();
};

SCClientSocket.prototype.deauthenticate = function (callback) {
  var self = this;

  this.auth.removeToken(this.authTokenName, function (err, oldToken) {
    if (err) {
      // Non-fatal error - Do not close the connection
      self._onSCError(err);
    } else {
      Emitter.prototype.emit.call(self, 'removeAuthToken', oldToken);
      if (self.state !== self.CLOSED) {
        self.emit('#removeAuthToken');
      }
      self._changeToUnauthenticatedStateAndClearTokens();
    }
    callback && callback(err);
  });
};

SCClientSocket.prototype.connect = SCClientSocket.prototype.open = function () {
  var self = this;

  if (!this.active) {
    var error = new InvalidActionError('Cannot connect a destroyed client');
    this._onSCError(error);
    return;
  }

  if (this.state === this.CLOSED) {
    this.pendingReconnect = false;
    this.pendingReconnectTimeout = null;
    clearTimeout(this._reconnectTimeoutRef);

    this.state = this.CONNECTING;
    Emitter.prototype.emit.call(this, 'connecting');

    if (this.transport) {
      this.transport.off();
    }

    this.transport = new SCTransport(this.auth, this.codec, this.options);

    this.transport.on('open', function (status) {
      self.state = self.OPEN;
      self._onSCOpen(status);
    });

    this.transport.on('error', function (err) {
      self._onSCError(err);
    });

    this.transport.on('close', function (code, data) {
      self.state = self.CLOSED;
      self._onSCClose(code, data);
    });

    this.transport.on('openAbort', function (code, data) {
      self.state = self.CLOSED;
      self._onSCClose(code, data, true);
    });

    this.transport.on('event', function (event, data, res) {
      self._onSCEvent(event, data, res);
    });
  }
};

SCClientSocket.prototype.reconnect = function (code, data) {
  this.disconnect(code, data);
  this.connect();
};

SCClientSocket.prototype.disconnect = function (code, data) {
  code = code || 1000;

  if (typeof code !== 'number') {
    throw new InvalidArgumentsError('If specified, the code argument must be a number');
  }

  if (this.state === this.OPEN || this.state === this.CONNECTING) {
    this.transport.close(code, data);
  } else {
    this.pendingReconnect = false;
    this.pendingReconnectTimeout = null;
    clearTimeout(this._reconnectTimeoutRef);
  }
};

SCClientSocket.prototype.destroy = function (code, data) {
  if (isBrowser && global.removeEventListener) {
    global.removeEventListener('beforeunload', this._unloadHandler, false);
  }
  this.active = false;
  this.disconnect(code, data);
  delete this._clientMap[this.clientId];
};

SCClientSocket.prototype._changeToUnauthenticatedStateAndClearTokens = function () {
  if (this.authState !== this.UNAUTHENTICATED) {
    var oldState = this.authState;
    var oldSignedToken = this.signedAuthToken;
    this.authState = this.UNAUTHENTICATED;
    this.signedAuthToken = null;
    this.authToken = null;

    var stateChangeData = {
      oldState: oldState,
      newState: this.authState
    };
    Emitter.prototype.emit.call(this, 'authStateChange', stateChangeData);
    Emitter.prototype.emit.call(this, 'deauthenticate', oldSignedToken);
  }
};

SCClientSocket.prototype._changeToAuthenticatedState = function (signedAuthToken) {
  this.signedAuthToken = signedAuthToken;
  this.authToken = this._extractAuthTokenData(signedAuthToken);

  if (this.authState !== this.AUTHENTICATED) {
    var oldState = this.authState;
    this.authState = this.AUTHENTICATED;
    var stateChangeData = {
      oldState: oldState,
      newState: this.authState,
      signedAuthToken: signedAuthToken,
      authToken: this.authToken
    };
    if (!this.preparingPendingSubscriptions) {
      this.processPendingSubscriptions();
    }

    Emitter.prototype.emit.call(this, 'authStateChange', stateChangeData);
  }
  Emitter.prototype.emit.call(this, 'authenticate', signedAuthToken);
};

SCClientSocket.prototype.decodeBase64 = function (encodedString) {
  var decodedString;
  if (typeof Buffer === 'undefined') {
    if (global.atob) {
      decodedString = global.atob(encodedString);
    } else {
      decodedString = base64.decode(encodedString);
    }
  } else {
    var buffer = Buffer.from(encodedString, 'base64');
    decodedString = buffer.toString('utf8');
  }
  return decodedString;
};

SCClientSocket.prototype.encodeBase64 = function (decodedString) {
  var encodedString;
  if (typeof Buffer === 'undefined') {
    if (global.btoa) {
      encodedString = global.btoa(decodedString);
    } else {
      encodedString = base64.encode(decodedString);
    }
  } else {
    var buffer = Buffer.from(decodedString, 'utf8');
    encodedString = buffer.toString('base64');
  }
  return encodedString;
};

SCClientSocket.prototype._extractAuthTokenData = function (signedAuthToken) {
  var tokenParts = (signedAuthToken || '').split('.');
  var encodedTokenData = tokenParts[1];
  if (encodedTokenData != null) {
    var tokenData = encodedTokenData;
    try {
      tokenData = this.decodeBase64(tokenData);
      return JSON.parse(tokenData);
    } catch (e) {
      return tokenData;
    }
  }
  return null;
};

SCClientSocket.prototype.getAuthToken = function () {
  return this.authToken;
};

SCClientSocket.prototype.getSignedAuthToken = function () {
  return this.signedAuthToken;
};

// Perform client-initiated authentication by providing an encrypted token string.
SCClientSocket.prototype.authenticate = function (signedAuthToken, callback) {
  var self = this;

  this.emit('#authenticate', signedAuthToken, function (err, authStatus) {
    if (authStatus && authStatus.isAuthenticated != null) {
      // If authStatus is correctly formatted (has an isAuthenticated property),
      // then we will rehydrate the authError.
      if (authStatus.authError) {
        authStatus.authError = scErrors.hydrateError(authStatus.authError);
      }
    } else {
      // Some errors like BadConnectionError and TimeoutError will not pass a valid
      // authStatus object to the current function, so we need to create it ourselves.
      authStatus = {
        isAuthenticated: self.authState,
        authError: null
      };
    }
    if (err) {
      if (err.name !== 'BadConnectionError' && err.name !== 'TimeoutError') {
        // In case of a bad/closed connection or a timeout, we maintain the last
        // known auth state since those errors don't mean that the token is invalid.

        self._changeToUnauthenticatedStateAndClearTokens();
      }
      callback && callback(err, authStatus);
    } else {
      self.auth.saveToken(self.authTokenName, signedAuthToken, {}, function (err) {
        if (err) {
          self._onSCError(err);
        }
        if (authStatus.isAuthenticated) {
          self._changeToAuthenticatedState(signedAuthToken);
        } else {
          self._changeToUnauthenticatedStateAndClearTokens();
        }
        callback && callback(err, authStatus);
      });
    }
  });
};

SCClientSocket.prototype._tryReconnect = function (initialDelay) {
  var self = this;

  var exponent = this.connectAttempts++;
  var reconnectOptions = this.options.autoReconnectOptions;
  var timeout;

  if (initialDelay == null || exponent > 0) {
    var initialTimeout = Math.round(reconnectOptions.initialDelay + (reconnectOptions.randomness || 0) * Math.random());

    timeout = Math.round(initialTimeout * Math.pow(reconnectOptions.multiplier, exponent));
  } else {
    timeout = initialDelay;
  }

  if (timeout > reconnectOptions.maxDelay) {
    timeout = reconnectOptions.maxDelay;
  }

  clearTimeout(this._reconnectTimeoutRef);

  this.pendingReconnect = true;
  this.pendingReconnectTimeout = timeout;
  this._reconnectTimeoutRef = setTimeout(function () {
    self.connect();
  }, timeout);
};

SCClientSocket.prototype._onSCOpen = function (status) {
  var self = this;

  this.preparingPendingSubscriptions = true;

  if (status) {
    this.id = status.id;
    this.pingTimeout = status.pingTimeout;
    this.transport.pingTimeout = this.pingTimeout;
    if (status.isAuthenticated) {
      this._changeToAuthenticatedState(status.authToken);
    } else {
      this._changeToUnauthenticatedStateAndClearTokens();
    }
  } else {
    // This can happen if auth.loadToken (in sctransport.js) fails with
    // an error - This means that the signedAuthToken cannot be loaded by
    // the auth engine and therefore, we need to unauthenticate the client.
    this._changeToUnauthenticatedStateAndClearTokens();
  }

  this.connectAttempts = 0;

  if (this.options.autoSubscribeOnConnect) {
    this.processPendingSubscriptions();
  }

  // If the user invokes the callback while in autoSubscribeOnConnect mode, it
  // won't break anything.
  Emitter.prototype.emit.call(this, 'connect', status, function () {
    self.processPendingSubscriptions();
  });

  if (this.state === this.OPEN) {
    this._flushEmitBuffer();
  }
};

SCClientSocket.prototype._onSCError = function (err) {
  var self = this;

  // Throw error in different stack frame so that error handling
  // cannot interfere with a reconnect action.
  setTimeout(function () {
    if (self.listeners('error').length < 1) {
      throw err;
    } else {
      Emitter.prototype.emit.call(self, 'error', err);
    }
  }, 0);
};

SCClientSocket.prototype._suspendSubscriptions = function () {
  var channel, newState;
  for (var channelName in this.channels) {
    if (this.channels.hasOwnProperty(channelName)) {
      channel = this.channels[channelName];
      if (channel.state === channel.SUBSCRIBED ||
        channel.state === channel.PENDING) {

        newState = channel.PENDING;
      } else {
        newState = channel.UNSUBSCRIBED;
      }

      this._triggerChannelUnsubscribe(channel, newState);
    }
  }
};

SCClientSocket.prototype._abortAllPendingEventsDueToBadConnection = function (failureType) {
  var currentNode = this._emitBuffer.head;
  var nextNode;

  while (currentNode) {
    nextNode = currentNode.next;
    var eventObject = currentNode.data;
    clearTimeout(eventObject.timeout);
    delete eventObject.timeout;
    currentNode.detach();
    currentNode = nextNode;

    var callback = eventObject.callback;
    if (callback) {
      delete eventObject.callback;
      var errorMessage = "Event '" + eventObject.event +
        "' was aborted due to a bad connection";
      var error = new BadConnectionError(errorMessage, failureType);
      callback.call(eventObject, error, eventObject);
    }
    // Cleanup any pending response callback in the transport layer too.
    if (eventObject.cid) {
      this.transport.cancelPendingResponse(eventObject.cid);
    }
  }
};

SCClientSocket.prototype._onSCClose = function (code, data, openAbort) {
  var self = this;

  this.id = null;

  if (this.transport) {
    this.transport.off();
  }
  this.pendingReconnect = false;
  this.pendingReconnectTimeout = null;
  clearTimeout(this._reconnectTimeoutRef);

  this._suspendSubscriptions();
  this._abortAllPendingEventsDueToBadConnection(openAbort ? 'connectAbort' : 'disconnect');

  // Try to reconnect
  // on server ping timeout (4000)
  // or on client pong timeout (4001)
  // or on close without status (1005)
  // or on handshake failure (4003)
  // or on handshake rejection (4008)
  // or on socket hung up (1006)
  if (this.options.autoReconnect) {
    if (code === 4000 || code === 4001 || code === 1005) {
      // If there is a ping or pong timeout or socket closes without
      // status, don't wait before trying to reconnect - These could happen
      // if the client wakes up after a period of inactivity and in this case we
      // want to re-establish the connection as soon as possible.
      this._tryReconnect(0);

      // Codes 4500 and above will be treated as permanent disconnects.
      // Socket will not try to auto-reconnect.
    } else if (code !== 1000 && code < 4500) {
      this._tryReconnect();
    }
  }

  if (openAbort) {
    Emitter.prototype.emit.call(self, 'connectAbort', code, data);
  } else {
    Emitter.prototype.emit.call(self, 'disconnect', code, data);
  }
  Emitter.prototype.emit.call(self, 'close', code, data);

  if (!SCClientSocket.ignoreStatuses[code]) {
    var closeMessage;
    if (data) {
      closeMessage = 'Socket connection closed with status code ' + code + ' and reason: ' + data;
    } else {
      closeMessage = 'Socket connection closed with status code ' + code;
    }
    var err = new SocketProtocolError(SCClientSocket.errorStatuses[code] || closeMessage, code);
    this._onSCError(err);
  }
};

SCClientSocket.prototype._onSCEvent = function (event, data, res) {
  var handler = this._privateEventHandlerMap[event];
  if (handler) {
    handler.call(this, data, res);
  } else {
    Emitter.prototype.emit.call(this, event, data, function () {
      res && res.callback.apply(res, arguments);
    });
  }
};

SCClientSocket.prototype.decode = function (message) {
  return this.transport.decode(message);
};

SCClientSocket.prototype.encode = function (object) {
  return this.transport.encode(object);
};

SCClientSocket.prototype._flushEmitBuffer = function () {
  var currentNode = this._emitBuffer.head;
  var nextNode;

  while (currentNode) {
    nextNode = currentNode.next;
    var eventObject = currentNode.data;
    currentNode.detach();
    this.transport.emitObject(eventObject);
    currentNode = nextNode;
  }
};

SCClientSocket.prototype._handleEventAckTimeout = function (eventObject, eventNode) {
  if (eventNode) {
    eventNode.detach();
  }
  delete eventObject.timeout;

  var callback = eventObject.callback;
  if (callback) {
    delete eventObject.callback;
    var error = new TimeoutError("Event response for '" + eventObject.event + "' timed out");
    callback.call(eventObject, error, eventObject);
  }
  // Cleanup any pending response callback in the transport layer too.
  if (eventObject.cid) {
    this.transport.cancelPendingResponse(eventObject.cid);
  }
};

SCClientSocket.prototype._emit = function (event, data, callback) {
  var self = this;

  if (this.state === this.CLOSED) {
    this.connect();
  }
  var eventObject = {
    event: event,
    callback: callback
  };

  var eventNode = new LinkedList.Item();

  if (this.options.cloneData) {
    eventObject.data = clone(data);
  } else {
    eventObject.data = data;
  }
  eventNode.data = eventObject;

  eventObject.timeout = setTimeout(function () {
    self._handleEventAckTimeout(eventObject, eventNode);
  }, this.ackTimeout);

  this._emitBuffer.append(eventNode);
  if (this.state === this.OPEN) {
    this._flushEmitBuffer();
  }
};

SCClientSocket.prototype.send = function (data) {
  this.transport.send(data);
};

SCClientSocket.prototype.emit = function (event, data, callback) {
  if (this._localEvents[event] == null) {
    this._emit(event, data, callback);
  } else if (event === 'error') {
    Emitter.prototype.emit.call(this, event, data);
  } else {
    var error = new InvalidActionError('The "' + event + '" event is reserved and cannot be emitted on a client socket');
    this._onSCError(error);
  }
};

SCClientSocket.prototype.publish = function (channelName, data, callback) {
  var pubData = {
    channel: this._decorateChannelName(channelName),
    data: data
  };
  this.emit('#publish', pubData, callback);
};

SCClientSocket.prototype._triggerChannelSubscribe = function (channel, subscriptionOptions) {
  var channelName = channel.name;

  if (channel.state !== channel.SUBSCRIBED) {
    var oldState = channel.state;
    channel.state = channel.SUBSCRIBED;

    var stateChangeData = {
      channel: channelName,
      oldState: oldState,
      newState: channel.state,
      subscriptionOptions: subscriptionOptions
    };
    channel.emit('subscribeStateChange', stateChangeData);
    channel.emit('subscribe', channelName, subscriptionOptions);
    Emitter.prototype.emit.call(this, 'subscribeStateChange', stateChangeData);
    Emitter.prototype.emit.call(this, 'subscribe', channelName, subscriptionOptions);
  }
};

SCClientSocket.prototype._triggerChannelSubscribeFail = function (err, channel, subscriptionOptions) {
  var channelName = channel.name;
  var meetsAuthRequirements = !channel.waitForAuth || this.authState === this.AUTHENTICATED;

  if (channel.state !== channel.UNSUBSCRIBED && meetsAuthRequirements) {
    channel.state = channel.UNSUBSCRIBED;

    channel.emit('subscribeFail', err, channelName, subscriptionOptions);
    Emitter.prototype.emit.call(this, 'subscribeFail', err, channelName, subscriptionOptions);
  }
};

// Cancel any pending subscribe callback
SCClientSocket.prototype._cancelPendingSubscribeCallback = function (channel) {
  if (channel._pendingSubscriptionCid != null) {
    this.transport.cancelPendingResponse(channel._pendingSubscriptionCid);
    delete channel._pendingSubscriptionCid;
  }
};

SCClientSocket.prototype._decorateChannelName = function (channelName) {
  if (this.channelPrefix) {
    channelName = this.channelPrefix + channelName;
  }
  return channelName;
};

SCClientSocket.prototype._undecorateChannelName = function (decoratedChannelName) {
  if (this.channelPrefix && decoratedChannelName.indexOf(this.channelPrefix) === 0) {
    return decoratedChannelName.replace(this.channelPrefix, '');
  }
  return decoratedChannelName;
};

SCClientSocket.prototype._trySubscribe = function (channel) {
  var self = this;

  var meetsAuthRequirements = !channel.waitForAuth || this.authState === this.AUTHENTICATED;

  // We can only ever have one pending subscribe action at any given time on a channel
  if (this.state === this.OPEN && !this.preparingPendingSubscriptions &&
    channel._pendingSubscriptionCid == null && meetsAuthRequirements) {

    var options = {
      noTimeout: true
    };

    var subscriptionOptions = {
      channel: this._decorateChannelName(channel.name)
    };
    if (channel.waitForAuth) {
      options.waitForAuth = true;
      subscriptionOptions.waitForAuth = options.waitForAuth;
    }
    if (channel.data) {
      subscriptionOptions.data = channel.data;
    }
    if (channel.batch) {
      options.batch = true;
      subscriptionOptions.batch = true;
    }

    channel._pendingSubscriptionCid = this.transport.emit(
      '#subscribe', subscriptionOptions, options,
      function (err) {
        delete channel._pendingSubscriptionCid;
        if (err) {
          self._triggerChannelSubscribeFail(err, channel, subscriptionOptions);
        } else {
          self._triggerChannelSubscribe(channel, subscriptionOptions);
        }
      }
    );
    Emitter.prototype.emit.call(this, 'subscribeRequest', channel.name, subscriptionOptions);
  }
};

SCClientSocket.prototype.subscribe = function (channelName, options) {
  var channel = this.channels[channelName];

  if (!channel) {
    channel = new SCChannel(channelName, this, options);
    this.channels[channelName] = channel;
  } else if (options) {
    channel.setOptions(options);
  }

  if (channel.state === channel.UNSUBSCRIBED) {
    channel.state = channel.PENDING;
    this._trySubscribe(channel);
  }

  return channel;
};

SCClientSocket.prototype._triggerChannelUnsubscribe = function (channel, newState) {
  var channelName = channel.name;
  var oldState = channel.state;

  if (newState) {
    channel.state = newState;
  } else {
    channel.state = channel.UNSUBSCRIBED;
  }
  this._cancelPendingSubscribeCallback(channel);

  if (oldState === channel.SUBSCRIBED) {
    var stateChangeData = {
      channel: channelName,
      oldState: oldState,
      newState: channel.state
    };
    channel.emit('subscribeStateChange', stateChangeData);
    channel.emit('unsubscribe', channelName);
    Emitter.prototype.emit.call(this, 'subscribeStateChange', stateChangeData);
    Emitter.prototype.emit.call(this, 'unsubscribe', channelName);
  }
};

SCClientSocket.prototype._tryUnsubscribe = function (channel) {
  var self = this;

  if (this.state === this.OPEN) {
    var options = {
      noTimeout: true
    };
    if (channel.batch) {
      options.batch = true;
    }
    // If there is a pending subscribe action, cancel the callback
    this._cancelPendingSubscribeCallback(channel);

    // This operation cannot fail because the TCP protocol guarantees delivery
    // so long as the connection remains open. If the connection closes,
    // the server will automatically unsubscribe the client and thus complete
    // the operation on the server side.
    var decoratedChannelName = this._decorateChannelName(channel.name);
    this.transport.emit('#unsubscribe', decoratedChannelName, options);
  }
};

SCClientSocket.prototype.unsubscribe = function (channelName) {
  var channel = this.channels[channelName];

  if (channel) {
    if (channel.state !== channel.UNSUBSCRIBED) {
      this._triggerChannelUnsubscribe(channel);
      this._tryUnsubscribe(channel);
    }
  }
};

SCClientSocket.prototype.channel = function (channelName, options) {
  var currentChannel = this.channels[channelName];

  if (!currentChannel) {
    currentChannel = new SCChannel(channelName, this, options);
    this.channels[channelName] = currentChannel;
  }
  return currentChannel;
};

SCClientSocket.prototype.destroyChannel = function (channelName) {
  var channel = this.channels[channelName];

  if (channel) {
    channel.unwatch();
    channel.unsubscribe();
    delete this.channels[channelName];
  }
};

SCClientSocket.prototype.subscriptions = function (includePending) {
  var subs = [];
  var channel, includeChannel;
  for (var channelName in this.channels) {
    if (this.channels.hasOwnProperty(channelName)) {
      channel = this.channels[channelName];

      if (includePending) {
        includeChannel = channel && (channel.state === channel.SUBSCRIBED ||
          channel.state === channel.PENDING);
      } else {
        includeChannel = channel && channel.state === channel.SUBSCRIBED;
      }

      if (includeChannel) {
        subs.push(channelName);
      }
    }
  }
  return subs;
};

SCClientSocket.prototype.isSubscribed = function (channelName, includePending) {
  var channel = this.channels[channelName];
  if (includePending) {
    return !!channel && (channel.state === channel.SUBSCRIBED ||
      channel.state === channel.PENDING);
  }
  return !!channel && channel.state === channel.SUBSCRIBED;
};

SCClientSocket.prototype.processPendingSubscriptions = function () {
  var self = this;

  this.preparingPendingSubscriptions = false;

  var pendingChannels = [];

  for (var i in this.channels) {
    if (this.channels.hasOwnProperty(i)) {
      var channel = this.channels[i];
      if (channel.state === channel.PENDING) {
        pendingChannels.push(channel);
      }
    }
  }

  pendingChannels.sort(function (a, b) {
    var ap = a.priority || 0;
    var bp = b.priority || 0;
    if (ap > bp) {
      return -1;
    }
    if (ap < bp) {
      return 1;
    }
    return 0;
  });

  pendingChannels.forEach(function (channel) {
    self._trySubscribe(channel);
  });
};

SCClientSocket.prototype.watch = function (channelName, handler) {
  if (typeof handler !== 'function') {
    throw new InvalidArgumentsError('No handler function was provided');
  }
  this._channelEmitter.on(channelName, handler);
};

SCClientSocket.prototype.unwatch = function (channelName, handler) {
  if (handler) {
    this._channelEmitter.removeListener(channelName, handler);
  } else {
    this._channelEmitter.removeAllListeners(channelName);
  }
};

SCClientSocket.prototype.watchers = function (channelName) {
  return this._channelEmitter.listeners(channelName);
};

module.exports = SCClientSocket;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {},require("buffer").Buffer)
},{"./auth":132,"./response":134,"./sctransport":136,"base-64":15,"buffer":17,"clone":18,"component-emitter":19,"linked-list":115,"querystring":124,"sc-channel":127,"sc-errors":129,"sc-formatter":130}],136:[function(require,module,exports){
(function (global){
var Emitter = require('component-emitter');
var Response = require('./response').Response;
var querystring = require('querystring');
var WebSocket;
var createWebSocket;

if (global.WebSocket) {
  WebSocket = global.WebSocket;
  createWebSocket = function (uri, options) {
    return new WebSocket(uri);
  };
} else {
  WebSocket = require('ws');
  createWebSocket = function (uri, options) {
    return new WebSocket(uri, null, options);
  };
}

var scErrors = require('sc-errors');
var TimeoutError = scErrors.TimeoutError;
var BadConnectionError = scErrors.BadConnectionError;


var SCTransport = function (authEngine, codecEngine, options) {
  var self = this;

  this.state = this.CLOSED;
  this.auth = authEngine;
  this.codec = codecEngine;
  this.options = options;
  this.connectTimeout = options.connectTimeout;
  this.pingTimeout = options.ackTimeout;
  this.pingTimeoutDisabled = !!options.pingTimeoutDisabled;
  this.callIdGenerator = options.callIdGenerator;
  this.authTokenName = options.authTokenName;

  this._pingTimeoutTicker = null;
  this._callbackMap = {};
  this._batchSendList = [];

  // Open the connection.

  this.state = this.CONNECTING;
  var uri = this.uri();

  var wsSocket = createWebSocket(uri, this.options);
  wsSocket.binaryType = this.options.binaryType;

  this.socket = wsSocket;

  wsSocket.onopen = function () {
    self._onOpen();
  };

  wsSocket.onclose = function (event) {
    var code;
    if (event.code == null) {
      // This is to handle an edge case in React Native whereby
      // event.code is undefined when the mobile device is locked.
      // TODO: This is not perfect since this condition could also apply to
      // an abnormal close (no close control frame) which would be a 1006.
      code = 1005;
    } else {
      code = event.code;
    }
    self._onClose(code, event.reason);
  };

  wsSocket.onmessage = function (message, flags) {
    self._onMessage(message.data);
  };

  wsSocket.onerror = function (error) {
    // The onclose event will be called automatically after the onerror event
    // if the socket is connected - Otherwise, if it's in the middle of
    // connecting, we want to close it manually with a 1006 - This is necessary
    // to prevent inconsistent behavior when running the client in Node.js
    // vs in a browser.

    if (self.state === self.CONNECTING) {
      self._onClose(1006);
    }
  };

  this._connectTimeoutRef = setTimeout(function () {
    self._onClose(4007);
    self.socket.close(4007);
  }, this.connectTimeout);
};

SCTransport.prototype = Object.create(Emitter.prototype);

SCTransport.CONNECTING = SCTransport.prototype.CONNECTING = 'connecting';
SCTransport.OPEN = SCTransport.prototype.OPEN = 'open';
SCTransport.CLOSED = SCTransport.prototype.CLOSED = 'closed';

SCTransport.prototype.uri = function () {
  var query = this.options.query || {};
  var schema = this.options.secure ? 'wss' : 'ws';

  if (this.options.timestampRequests) {
    query[this.options.timestampParam] = (new Date()).getTime();
  }

  query = querystring.encode(query);

  if (query.length) {
    query = '?' + query;
  }

  var host;
  if (this.options.host) {
    host = this.options.host;
  } else {
    var port = '';

    if (this.options.port && ((schema === 'wss' && this.options.port !== 443)
      || (schema === 'ws' && this.options.port !== 80))) {
      port = ':' + this.options.port;
    }
    host = this.options.hostname + port;
  }

  return schema + '://' + host + this.options.path + query;
};

SCTransport.prototype._onOpen = function () {
  var self = this;

  clearTimeout(this._connectTimeoutRef);
  this._resetPingTimeout();

  this._handshake(function (err, status) {
    if (err) {
      var statusCode;
      if (status && status.code) {
        statusCode = status.code;
      } else {
        statusCode = 4003;
      }
      self._onError(err);
      self._onClose(statusCode, err.toString());
      self.socket.close(statusCode);
    } else {
      self.state = self.OPEN;
      Emitter.prototype.emit.call(self, 'open', status);
      self._resetPingTimeout();
    }
  });
};

SCTransport.prototype._handshake = function (callback) {
  var self = this;
  this.auth.loadToken(this.authTokenName, function (err, token) {
    if (err) {
      callback(err);
    } else {
      // Don't wait for this.state to be 'open'.
      // The underlying WebSocket (this.socket) is already open.
      var options = {
        force: true
      };
      self.emit('#handshake', {
        authToken: token
      }, options, function (err, status) {
        if (status) {
          // Add the token which was used as part of authentication attempt
          // to the status object.
          status.authToken = token;
          if (status.authError) {
            status.authError = scErrors.hydrateError(status.authError);
          }
        }
        callback(err, status);
      });
    }
  });
};

SCTransport.prototype._abortAllPendingEventsDueToBadConnection = function (failureType) {
  for (var i in this._callbackMap) {
    if (this._callbackMap.hasOwnProperty(i)) {
      var eventObject = this._callbackMap[i];
      delete this._callbackMap[i];

      clearTimeout(eventObject.timeout);
      delete eventObject.timeout;

      var errorMessage = "Event '" + eventObject.event +
        "' was aborted due to a bad connection";
      var badConnectionError = new BadConnectionError(errorMessage, failureType);

      var callback = eventObject.callback;
      delete eventObject.callback;
      callback.call(eventObject, badConnectionError, eventObject);
    }
  }
};

SCTransport.prototype._onClose = function (code, data) {
  delete this.socket.onopen;
  delete this.socket.onclose;
  delete this.socket.onmessage;
  delete this.socket.onerror;

  clearTimeout(this._connectTimeoutRef);
  clearTimeout(this._pingTimeoutTicker);
  clearTimeout(this._batchTimeout);

  if (this.state === this.OPEN) {
    this.state = this.CLOSED;
    Emitter.prototype.emit.call(this, 'close', code, data);
    this._abortAllPendingEventsDueToBadConnection('disconnect');

  } else if (this.state === this.CONNECTING) {
    this.state = this.CLOSED;
    Emitter.prototype.emit.call(this, 'openAbort', code, data);
    this._abortAllPendingEventsDueToBadConnection('connectAbort');
  }
};

SCTransport.prototype._handleEventObject = function (obj, message) {
  if (obj && obj.event != null) {
    var response = new Response(this, obj.cid);
    Emitter.prototype.emit.call(this, 'event', obj.event, obj.data, response);
  } else if (obj && obj.rid != null) {
    var eventObject = this._callbackMap[obj.rid];
    if (eventObject) {
      clearTimeout(eventObject.timeout);
      delete eventObject.timeout;
      delete this._callbackMap[obj.rid];

      if (eventObject.callback) {
        var rehydratedError = scErrors.hydrateError(obj.error);
        eventObject.callback(rehydratedError, obj.data);
      }
    }
  } else {
    Emitter.prototype.emit.call(this, 'event', 'raw', message);
  }
};

SCTransport.prototype._onMessage = function (message) {
  Emitter.prototype.emit.call(this, 'event', 'message', message);

  var obj = this.decode(message);

  // If ping
  if (obj === '#1') {
    this._resetPingTimeout();
    if (this.socket.readyState === this.socket.OPEN) {
      this.sendObject('#2');
    }
  } else {
    if (Array.isArray(obj)) {
      var len = obj.length;
      for (var i = 0; i < len; i++) {
        this._handleEventObject(obj[i], message);
      }
    } else {
      this._handleEventObject(obj, message);
    }
  }
};

SCTransport.prototype._onError = function (err) {
  Emitter.prototype.emit.call(this, 'error', err);
};

SCTransport.prototype._resetPingTimeout = function () {
  if (this.pingTimeoutDisabled) {
    return;
  }
  var self = this;

  var now = (new Date()).getTime();
  clearTimeout(this._pingTimeoutTicker);

  this._pingTimeoutTicker = setTimeout(function () {
    self._onClose(4000);
    self.socket.close(4000);
  }, this.pingTimeout);
};

SCTransport.prototype.getBytesReceived = function () {
  return this.socket.bytesReceived;
};

SCTransport.prototype.close = function (code, data) {
  code = code || 1000;

  if (this.state === this.OPEN) {
    var packet = {
      code: code,
      data: data
    };
    this.emit('#disconnect', packet);

    this._onClose(code, data);
    this.socket.close(code);

  } else if (this.state === this.CONNECTING) {
    this._onClose(code, data);
    this.socket.close(code);
  }
};

SCTransport.prototype.emitObject = function (eventObject, options) {
  var simpleEventObject = {
    event: eventObject.event,
    data: eventObject.data
  };

  if (eventObject.callback) {
    simpleEventObject.cid = eventObject.cid = this.callIdGenerator();
    this._callbackMap[eventObject.cid] = eventObject;
  }

  this.sendObject(simpleEventObject, options);

  return eventObject.cid || null;
};

SCTransport.prototype._handleEventAckTimeout = function (eventObject) {
  if (eventObject.cid) {
    delete this._callbackMap[eventObject.cid];
  }
  delete eventObject.timeout;

  var callback = eventObject.callback;
  if (callback) {
    delete eventObject.callback;
    var error = new TimeoutError("Event response for '" + eventObject.event + "' timed out");
    callback.call(eventObject, error, eventObject);
  }
};

// The last two optional arguments (a and b) can be options and/or callback
SCTransport.prototype.emit = function (event, data, a, b) {
  var self = this;

  var callback, options;

  if (b) {
    options = a;
    callback = b;
  } else {
    if (a instanceof Function) {
      options = {};
      callback = a;
    } else {
      options = a;
    }
  }

  var eventObject = {
    event: event,
    data: data,
    callback: callback
  };

  if (callback && !options.noTimeout) {
    eventObject.timeout = setTimeout(function () {
      self._handleEventAckTimeout(eventObject);
    }, this.options.ackTimeout);
  }

  var cid = null;
  if (this.state === this.OPEN || options.force) {
    cid = this.emitObject(eventObject, options);
  }
  return cid;
};

SCTransport.prototype.cancelPendingResponse = function (cid) {
  delete this._callbackMap[cid];
};

SCTransport.prototype.decode = function (message) {
  return this.codec.decode(message);
};

SCTransport.prototype.encode = function (object) {
  return this.codec.encode(object);
};

SCTransport.prototype.send = function (data) {
  if (this.socket.readyState !== this.socket.OPEN) {
    this._onClose(1005);
  } else {
    this.socket.send(data);
  }
};

SCTransport.prototype.serializeObject = function (object) {
  var str, formatError;
  try {
    str = this.encode(object);
  } catch (err) {
    formatError = err;
    this._onError(formatError);
  }
  if (!formatError) {
    return str;
  }
  return null;
};

SCTransport.prototype.sendObjectBatch = function (object) {
  var self = this;

  this._batchSendList.push(object);
  if (this._batchTimeout) {
    return;
  }

  this._batchTimeout = setTimeout(function () {
    delete self._batchTimeout;
    if (self._batchSendList.length) {
      var str = self.serializeObject(self._batchSendList);
      if (str != null) {
        self.send(str);
      }
      self._batchSendList = [];
    }
  }, this.options.pubSubBatchDuration || 0);
};

SCTransport.prototype.sendObjectSingle = function (object) {
  var str = this.serializeObject(object);
  if (str != null) {
    this.send(str);
  }
};

SCTransport.prototype.sendObject = function (object, options) {
  if (options && options.batch) {
    this.sendObjectBatch(object);
  } else {
    this.sendObjectSingle(object);
  }
};

module.exports.SCTransport = SCTransport;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./response":134,"component-emitter":19,"querystring":124,"sc-errors":129,"ws":137}],137:[function(require,module,exports){
var global;
if (typeof WorkerGlobalScope !== 'undefined') {
  global = self;
} else {
  global = typeof window !== 'undefined' && window || (function() { return this; })();
}

var WebSocket = global.WebSocket || global.MozWebSocket;

/**
 * WebSocket constructor.
 *
 * The third `opts` options object gets ignored in web browsers, since it's
 * non-standard, and throws a TypeError if passed to the constructor.
 * See: https://github.com/einaros/ws/issues/227
 *
 * @param {String} uri
 * @param {Array} protocols (optional)
 * @param {Object} opts (optional)
 * @api public
 */

function ws(uri, protocols, opts) {
  var instance;
  if (protocols) {
    instance = new WebSocket(uri, protocols);
  } else {
    instance = new WebSocket(uri);
  }
  return instance;
}

if (WebSocket) ws.prototype = WebSocket.prototype;

module.exports = WebSocket ? ws : null;

},{}],138:[function(require,module,exports){
var v1 = require('./v1');
var v4 = require('./v4');

var uuid = v4;
uuid.v1 = v1;
uuid.v4 = v4;

module.exports = uuid;

},{"./v1":141,"./v4":142}],139:[function(require,module,exports){
/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
var byteToHex = [];
for (var i = 0; i < 256; ++i) {
  byteToHex[i] = (i + 0x100).toString(16).substr(1);
}

function bytesToUuid(buf, offset) {
  var i = offset || 0;
  var bth = byteToHex;
  return bth[buf[i++]] + bth[buf[i++]] +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] +
          bth[buf[i++]] + bth[buf[i++]] +
          bth[buf[i++]] + bth[buf[i++]];
}

module.exports = bytesToUuid;

},{}],140:[function(require,module,exports){
// Unique ID creation requires a high quality random # generator.  In the
// browser this is a little complicated due to unknown quality of Math.random()
// and inconsistent support for the `crypto` API.  We do the best we can via
// feature-detection

// getRandomValues needs to be invoked in a context where "this" is a Crypto implementation.
var getRandomValues = (typeof(crypto) != 'undefined' && crypto.getRandomValues.bind(crypto)) ||
                      (typeof(msCrypto) != 'undefined' && msCrypto.getRandomValues.bind(msCrypto));
if (getRandomValues) {
  // WHATWG crypto RNG - http://wiki.whatwg.org/wiki/Crypto
  var rnds8 = new Uint8Array(16); // eslint-disable-line no-undef

  module.exports = function whatwgRNG() {
    getRandomValues(rnds8);
    return rnds8;
  };
} else {
  // Math.random()-based (RNG)
  //
  // If all else fails, use Math.random().  It's fast, but is of unspecified
  // quality.
  var rnds = new Array(16);

  module.exports = function mathRNG() {
    for (var i = 0, r; i < 16; i++) {
      if ((i & 0x03) === 0) r = Math.random() * 0x100000000;
      rnds[i] = r >>> ((i & 0x03) << 3) & 0xff;
    }

    return rnds;
  };
}

},{}],141:[function(require,module,exports){
var rng = require('./lib/rng');
var bytesToUuid = require('./lib/bytesToUuid');

// **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html

var _nodeId;
var _clockseq;

// Previous uuid creation time
var _lastMSecs = 0;
var _lastNSecs = 0;

// See https://github.com/broofa/node-uuid for API details
function v1(options, buf, offset) {
  var i = buf && offset || 0;
  var b = buf || [];

  options = options || {};
  var node = options.node || _nodeId;
  var clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq;

  // node and clockseq need to be initialized to random values if they're not
  // specified.  We do this lazily to minimize issues related to insufficient
  // system entropy.  See #189
  if (node == null || clockseq == null) {
    var seedBytes = rng();
    if (node == null) {
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      node = _nodeId = [
        seedBytes[0] | 0x01,
        seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]
      ];
    }
    if (clockseq == null) {
      // Per 4.2.2, randomize (14 bit) clockseq
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
    }
  }

  // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.
  var msecs = options.msecs !== undefined ? options.msecs : new Date().getTime();

  // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock
  var nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1;

  // Time since last uuid creation (in msecs)
  var dt = (msecs - _lastMSecs) + (nsecs - _lastNSecs)/10000;

  // Per 4.2.1.2, Bump clockseq on clock regression
  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  }

  // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  }

  // Per 4.2.1.2 Throw error if too many uuids are requested
  if (nsecs >= 10000) {
    throw new Error('uuid.v1(): Can\'t create more than 10M uuids/sec');
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;

  // Per 4.1.4 - Convert from unix epoch to Gregorian epoch
  msecs += 12219292800000;

  // `time_low`
  var tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff;

  // `time_mid`
  var tmh = (msecs / 0x100000000 * 10000) & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff;

  // `time_high_and_version`
  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version
  b[i++] = tmh >>> 16 & 0xff;

  // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)
  b[i++] = clockseq >>> 8 | 0x80;

  // `clock_seq_low`
  b[i++] = clockseq & 0xff;

  // `node`
  for (var n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf ? buf : bytesToUuid(b);
}

module.exports = v1;

},{"./lib/bytesToUuid":139,"./lib/rng":140}],142:[function(require,module,exports){
var rng = require('./lib/rng');
var bytesToUuid = require('./lib/bytesToUuid');

function v4(options, buf, offset) {
  var i = buf && offset || 0;

  if (typeof(options) == 'string') {
    buf = options === 'binary' ? new Array(16) : null;
    options = null;
  }
  options = options || {};

  var rnds = options.random || (options.rng || rng)();

  // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`
  rnds[6] = (rnds[6] & 0x0f) | 0x40;
  rnds[8] = (rnds[8] & 0x3f) | 0x80;

  // Copy bytes to buffer, if provided
  if (buf) {
    for (var ii = 0; ii < 16; ++ii) {
      buf[i + ii] = rnds[ii];
    }
  }

  return buf || bytesToUuid(rnds);
}

module.exports = v4;

},{"./lib/bytesToUuid":139,"./lib/rng":140}]},{},[1])(1)
});
