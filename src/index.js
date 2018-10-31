import socketClient from 'socketcluster-client'
import common from 'masq-common'
import EventEmitter from 'events'
import MasqCrypto from 'masq-crypto'

// Those errors must be added into masq-common
let newErrors = {
  CHANNELNOTSUBSCRIBED: 'The channel is not subscribed',
  NOCOMMONKEY: 'The ECDH common key does not exist',
  NOECPRIVATEKEY: 'The EC private key does not exist',
  NORSAPUBLICKEYSTORED: 'The sender RSA public key does not exist',
  VERIFICATIONFAILED: 'The received EC public key verification failed, check the registered sender RSA public key',
  RSAEXCHANGEENCKEY: 'The ephemeral AES encryption key used to encrypt RSA public keys during pairing operation is not known'
}
let ERRORS = Object.assign(common.ERRORS, newErrors)

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
const DEFAULTS = {
  hostname: 'localhost',
  port: 9009,
  multiplex: false,
  autoReconnectOptions: {
    randomness: 1000,
    multiplier: 1.5,
    maxDelay: 7000
  }
}

const debug = false
var log = (...args) => {
  const reg = (all, cur) => {
    if (typeof (cur) === 'string') {
      return all + cur
    } else {
      return all + cur.toString()
    }
  }
  if (debug) {
    console.log('[Masq sync]', args.reduce(reg, ''))
  }
}

/**
 * Client class.
 *
 * @param  {Object} options List of constructor parameters
 * @param  {Object} options.ID The id of the socket (hash of the RSA public key)
 * @param  {Object} options.masqStore The instance of masq
 */
class Client extends EventEmitter {
  constructor (options) {
    super()
    // override default options
    this.options = Object.assign({}, DEFAULTS, options)
    this.ID = this.options.id || common.generateUUID()
    this.channels = {}
    this.RSAExchangeEncKey = null
    this.commonECDHDerivedKey = null
    this.EC = null
    this.RSA = null
    this.masqStore = this.options.masqStore
    this.socket = undefined
    this.myChannel = undefined
  }

  /**
   * Init a new socketClient connection.
   *
   * @return  {Promise} Promise resolves/rejects upon connection or errors
   */
  init () {
    return new Promise((resolve, reject) => {
      this.socket = socketClient.create(this.options)

      this.socket.on('error', (err) => {
        return reject(err)
      })

      this.socket.on('close', (err) => {
        return reject(err)
      })

      this.socket.on('connect', async () => {
        // Also subscribe this client to its own channel by default
        await this.subscribeSelf()
        return resolve()
      })
    })
  }

  /**
   * Send a message to the channel
   * @param {string} channel - The channel name
   * @param {Object} msg -  The message
   */
  sendMessage (channel, msg) {
    // checkParameter(msg)
    if (!this.channels[channel]) {
      throw common.generateError(ERRORS.CHANNELNOTSUBSCRIBED)
    }
    this.channels[channel].socket.publish(msg)
  }

  /**
   * This function stores the RSAExchangeEncKey in the current masq-sync
   * instance to en/decrypt the exchanged of the RSA public keys during
   * pairing operation/communications.
   *
   * @param {string} RSAExchangeEncKey - The hexadecimal string of the symmetric key (128bits)
   */
  saveRSAExchangeEncKey (RSAExchangeEncKey) {
    this.RSAExchangeEncKey = MasqCrypto.utils.hexStringToBuffer(RSAExchangeEncKey)
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
  async sendRSAPublicKey (params) {
    if (params.symmetricKey) {
      this.RSAExchangeEncKey = MasqCrypto.utils.hexStringToBuffer(params.symmetricKey)
    }
    if (!params.symmetricKey && !this.RSAExchangeEncKey) {
      throw common.generateError(ERRORS.RSAEXCHANGEENCKEY)
    }
    const cipherAES = new MasqCrypto.AES({
      mode: MasqCrypto.aesModes.GCM,
      key: params.symmetricKey ? MasqCrypto.utils.hexStringToBuffer(params.symmetricKey) : this.RSAExchangeEncKey,
      keySize: 128
    })
    const currentDevice = await this.masqStore.getCurrentDevice()
    const encPublicKey = await cipherAES.encrypt(JSON.stringify(currentDevice.publicKeyRaw))
    let msg = {
      from: this.ID,
      event: 'publicKey',
      data: { key: encPublicKey },
      to: params.to,
      ack: params.ack
    }
    this.sendMessage(msg.to, msg)
  }

  /**
   * Send the EC public key along with associated signature
   * The EC key pair is generated and stored in this.EC
   * @param {Object} params - The EC public key exchange parameters
   * @param {string} params.to - The channel name
   * @param {boolean} ack - Indicate if this is a response to a previous event
   */
  async sendECPublicKey (params) {
    if (!this.EC) {
      this.EC = new MasqCrypto.EC({})
      await this.EC.genECKeyPair()
    }
    const ECPublicKey = await this.EC.exportKeyRaw()
    const currentDevice = await this.masqStore.getCurrentDevice()

    if (!this.RSA) {
      this.RSA = new MasqCrypto.RSA({})
      this.RSA.publicKey = currentDevice.publicKey
      this.RSA.privateKey = currentDevice.privateKey
    }
    const signature = await this.RSA.signRSA(ECPublicKey)
    let msg = {
      from: this.ID,
      event: 'ECPublicKey',
      to: params.to,
      ack: params.ack,
      data: {
        key: MasqCrypto.utils.bufferToHexString(ECPublicKey),
        signature: MasqCrypto.utils.bufferToHexString(signature)
      }
    }

    this.sendMessage(msg.to, msg)
  }

  /**
   * Send the group channel key, encrypted with common derived secret key (ECDH)
   * @param {Object} params - The group key exchange parameters
   * @param {string} params.to - The channel name
   * @param {string} params.groupkey - The group key (hex string of a 128 bit AES key)
   */
  async sendChannelKey (params) {
    if (!this.commonECDHDerivedKey) {
      throw common.generateError(ERRORS.NOCOMMONKEY)
    }
    const cipherAES = new MasqCrypto.AES({
      mode: MasqCrypto.aesModes.GCM,
      key: this.commonECDHDerivedKey,
      keySize: 128
    })
    const encGroupKey = await cipherAES.encrypt(params.groupkey)

    let msg = {
      to: params.to,
      event: 'channelKey',
      from: this.ID,
      data: { key: encGroupKey }
    }
    this.sendMessage(msg.to, msg)
  }

  readyToTransfer (channel) {
    let msg = {
      event: 'readyToTransfer',
      from: this.ID
    }
    this.sendMessage(channel, msg)
  }

  /**
   * Decryption of the received RSA public key with this.RSAExchangeEncKey.
   * this.RSAExchangeEncKey is, stored by the device which generates it, i.e. the
   * device which is asked to be paired, and, retrieved by another channel for the
   * paired device.
   * @param {Object} key - The stringified and encrypted RSA public key
   * @return {Object} - The decrypted but still stringified RSA public key
   */
  async decryptRSAPublicKey (key) {
    const cipherAES = new MasqCrypto.AES({
      mode: MasqCrypto.aesModes.GCM,
      key: this.RSAExchangeEncKey,
      keySize: 128
    })
    const decPublicKey = await cipherAES.decrypt(key)
    return decPublicKey
  }
  async decryptGroupKey (msg) {
    if (!this.commonECDHDerivedKey) {
      throw common.generateError(ERRORS.NOCOMMONKEY)
    }
    const cipherAES = new MasqCrypto.AES({
      mode: MasqCrypto.aesModes.GCM,
      key: this.commonECDHDerivedKey,
      keySize: 128
    })
    const decGroupKey = await cipherAES.decrypt(msg.data.key)
    return decGroupKey
  }

  /**
   *
   * @param {string} from - The sender of the RSA public key
   * @param {Object} key - The stringified RSA public key
   */
  async storeRSAPublicKey (from, key) {
    let device = {
      name: from,
      RSAPublicKey: key,
      isSynched: true
    }
    log(device)
    await this.masqStore.addPairedDevice(device)
  }
  storeECPublicKey (msg) {

  }

  /**
   * Derive the common secret key - ECDH
   * this.EC.privateKey must exist
   * @param {string} senderECPublicKey - The hexadecimal string of of the sender EC public key
   */
  async deriveSecretKey (senderECPublicKey) {
    if (!this.EC.privateKey) {
      throw common.generateError(ERRORS.NOECPRIVATEKEY)
    }
    const ECPublicKey = MasqCrypto.utils.hexStringToBuffer(senderECPublicKey)
    const ECCryptoKey = await this.EC.importKeyRaw(ECPublicKey)
    this.commonECDHDerivedKey = await this.EC.deriveKeyECDH(ECCryptoKey, 'aes-gcm', 128)
  }

  /**
   *
   * @param {Object} data - The message data
   * @param {string} data.key - The hexadecimal string of of the sender EC public key
   * @param {string} data.signature - The hexadecimal string of the signature
   * @param {CryptoKey} senderRSAPublicKey - The RSA public key (jwt object)
   */
  async verifyReceivedECPublicKey (data, senderRSAPublicKey) {
    const ECPublicKey = MasqCrypto.utils.hexStringToBuffer(data.key)
    const signature = MasqCrypto.utils.hexStringToBuffer(data.signature)
    return MasqCrypto.RSA.verifRSA(senderRSAPublicKey, signature, ECPublicKey)
  }

  async handleGroupKey (msg) {
    const groupKey = await this.decryptGroupKey(msg)
    this.emit('channelKey', { key: groupKey, from: msg.from })
  }

  /**
  * Handle the received RSA public key
  * @param {ECPublicKeyMsgFormat} msg
  */
  async handleRSAPublicKey (msg) {
    const RSAPublicKey = await this.decryptRSAPublicKey(msg.data.key)
    this.storeRSAPublicKey(msg.from, RSAPublicKey)
    this.emit('RSAPublicKey', { key: RSAPublicKey, from: msg.from })
    if (msg.ack) { return }
    // If initial request, send the RSA public key
    let params = {
      to: msg.from,
      ack: true
    }
    this.sendRSAPublicKey(params)
  }

  /**
  * Handle the received EC public key
  * @param {ECPublicKeyMsgFormat} msg
  */
  async handleECPublicKey (msg) {
    const devices = await this.masqStore.listDevices()
    if (!devices[msg.from].RSAPublicKey) {
      throw common.generateError(ERRORS.NORSAPUBLICKEYSTORED)
    }
    // The RSAPublicKey is stringified, we must parse the key in order to import it.
    const senderRSAPublicKey = await MasqCrypto.RSA.importRSAPubKey(JSON.parse(devices[msg.from].RSAPublicKey))
    if (!this.verifyReceivedECPublicKey(msg.data, senderRSAPublicKey)) {
      throw common.generateError(ERRORS.VERIFICATIONFAILED)
    }

    if (msg.ack) {
      await this.deriveSecretKey(msg.data.key)
      this.emit('initECDH', { key: this.commonECDHDerivedKey, from: msg.from })
      this.readyToTransfer(msg.from)
    } else {
      // If initial request, send EC public key
      this.EC = new MasqCrypto.EC({})
      await this.EC.genECKeyPair()
      await this.deriveSecretKey(msg.data.key)
      let params = {
        to: msg.from,
        ack: true
      }
      this.sendECPublicKey(params)
    }
  }

  /**
   * Subscribe this client to its own channel.
   *
   * @return  {object} The WebSocket client
   */
  subscribeSelf () {
    this.myChannel = this.socket.subscribe(this.ID)

    this.myChannel.watch(msg => {
      log('****** RECEIVE ******')
      log(`From ${msg.from} : ${msg}`)
      log('****** RECEIVE ******')

      if (msg.from === this.ID) return
      if (msg.from) {
        log(`New msg in my channel:`, msg.event)
        if (msg.event === 'ping') {
          var data = {
            event: 'pong',
            from: this.ID
          }
          if (!this.channels[msg.from]) {
            // Subscribe to that user
            this.channels[msg.from] = {
              socket: this.socket.subscribe(msg.from)
            }
          }
          this.channels[msg.from].socket.publish(data)
          // log('Channel up with ' + msg.from)
        }
        if (msg.event === 'ECPublicKey') {
          this.handleECPublicKey(msg)
        }
        if (msg.event === 'readyToTransfer') {
          this.emit('initECDH', { key: this.commonECDHDerivedKey, from: msg.from })
        }
        if (msg.event === 'channelKey') {
          this.handleGroupKey(msg)
        }
        if (msg.event === 'publicKey') {
          this.handleRSAPublicKey(msg)
        }
      }
    })
  }
  /**
   * Subscribe peer to a given channel.
   *
   * @param   {string} peer A peer (device)
   * @param   {boolean} batch Whether to batch requests for increased perfomance
   * @return  {Promise} Promise resolves/rejects upon subscription or errors
   */
  subscribePeer (peer, batch = false) {
    return new Promise((resolve, reject) => {
      if (!peer || peer.length === 0) {
        return reject(new Error('Invalid peer value'))
      }
      this.channels[peer] = {
        socket: this.socket.subscribe(peer, {
          batch: batch
        })
      }
      this.channels[peer].socket.on('subscribe', () => {
        this.channels[peer].socket.publish({
          event: 'ping',
          from: this.ID
        })
        return resolve()
      })
      this.channels[peer].socket.on('subscribeFail', () => {
        return reject(new Error('Subscribe failed'))
      })
    })
  }

  /**
   * Subscribe a list of peers to a given channel.
   *
   * @param   {array} peers List of peers (devices)
   * @return  {Promise} Promise resolves/rejects upon subscription or errors
   */
  subscribePeers (peers = []) {
    if (!Array.isArray(peers)) {
      return Promise.reject(new Error('Invalid peer list'))
    }
    let pending = []
    peers.forEach((peer) => {
      const sub = this.subscribePeer(peer, true)
      sub.catch(() => {
        // do something with err
      })
      pending.push(sub)
    })
    return Promise.all(pending)
  }

  /**
   * Unsubscribe peer from a given channel.
   *
   * @param   {string} peer A peer (device)
   * @return  {Promise} Promise resolves/rejects upon unsubscription or errors
   */
  unsubscribePeer (peer) {
    return new Promise((resolve, reject) => {
      if (!peer || peer.length === 0 || this.channels[peer] === undefined) {
        return reject(new Error('Invalid peer value'))
      }
      this.channels[peer].socket.unsubscribe()
      delete this.channels[peer]
      return resolve()
    })
  }

  /**
   * Deterministically elect a master device, by using the first element of a
   * alphabetically ordered list of peers.
   *
   * @param   {array} peers List of peers (devices)
   * @return  {string} The peer ID of the master
   */
  electMaster (peers = []) {
    peers.push(this.ID)
    peers.sort()
    return peers[0]
  }
}

module.exports.Client = Client
