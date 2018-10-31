# PFS-demo-web-socket
A demo of PFS implementing ECDHE-RSA-AES128-GCM-SHA256 between two entities based on websocket communication.

This demo is based on : 
* masq-sync : to create a websocket peer
* masq-crypto : all the crypto operations are wrapped in masq-crypto which relies on webCryptoAPI
* masq-common : add some helpers for error handling

The demo simulates two devices which want to be paired and synchronised. The demo shows how to securely shared a session key (symmetric key) through ECDHE. 

The different steps are to : 
- Generate a long term RSA key pair in each device
- Sharing a link with a temporary symmetric key _RSAExchangeEncKey_ and a channel ID, both are hard coded for the demo purpose
- Connect to a webSocket channel, exchange the encrypted RSA public key with  _RSAExchangeEncKey_
- Now, the received public key will be used to autenticate (signature/verifiation) of the ephemeral EC public keys
- The next step is to start ECDHE by generating a EC key-pair, both devices can communicate by sending messages to a derived channel name (derivation of the received RSA public key)
- Signing and sending the EC public keys
- Verifying and, if verification is ok, deriving a common secret key
- Now the next message will be encrypted with the common secret key, this could be a session key (symmetric key)

By doing this way, after sending a session key, the EC key pair could be deleted, so even if an attacker is listening 
the network, he will not be able to get the common secret key (because the EC private is ephemeral and use once only to derive the common secret key).

The next legitimate question is : _how long will be used the session key ?_
The answer is : _it depends on the desired security level_

Signal protocol use a _Double Ratchet Algorithm_ to _derive_ the session key for each message. Another option is to have a expiration date for that session key of _1 day_, 1 _week_.


## Websocket 
Masq-sync allows to create peers and subsrcibed to a channel, a _socketcluster server_ must be running.

## Developer

```
git clone https://github.com/leventDem/PFS-demo-web-socket.git
cd PFS-demo-web-socket
npm install
```
## Demo

The demo works with a mocked version of MasqStore to manage the devices info. Data is stored only 
in volatile memory.

### Run demo

```
npm run start
```
Open [demo](http://127.0.0.1:8081/demo/pfs.html) in two browsers. Each browsers corresponds to a 
different device.



### Important note
The exchange of the initial RSA public key is **not secure** and does not prevent from **Man-in-the-middle attack**. The recommanded way is to share through another channel (link by e-mail or QrCode in mobile application) a temporary symmetric key and websocket channel id. 
Then, this temporary channel must be used to encrypt and share both devices RSA long term public key. 

From now on, they can communicate to each other channel, the channel name could be derived from the received public key for instance (hash). 
