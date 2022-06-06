# Iridium SBD 9602/9603 Transciever Emulator

## Overview
Emulator for Iridium SBD 9602/9603 transceiver modules. 

Using the com0com modem emulator available at https://sourceforge.net/projects/com0com/ users are able to create two virtual COM ports (eg. COM5 and COM6) which map to each other. You can connect your application to one of the COM ports and the emulator to the other COM port. The emulator will then read the input and write back out accordingly. Various configuration and options are available to make against the emulator library.

## Setup
1. Download and install the com0com null modem emulator from 
* https://lfs.connectgateway.app/utils/com0com-3.0.0.0-i386-and-x64-signed.zip 
* https://sourceforge.net/projects/com0com/files/latest/download 
2. Create a virtual com port pair using com0com

![Alt text](documentation/img/portpair.PNG?raw=true "Virtual Port Pair")

3. Create a new instance of the IridiumEmulator class

## Usage
```js
import jwt, { JwtPayload } from 'jsonwebtoken'

import { decompress } from './utils'
import { IridiumEmulator, SignalQualityRating } from './emulator'

const emulator = new IridiumEmulator({
  portPath: 'CNCB0',
  signalQualityRating: SignalQualityRating.GOOD,
})

let publicKey

emulator.on('sbd-message', (message) => {
  // verify the signed jwt with the public certificate
  const claims = jwt.verify(message.JWT, publicKey) as JwtPayload
  console.dir(claims)
  // decode the binary encoded string
  console.log(Buffer.from(claims.data, 'hex'))
  // decompress the binary encoded string
  console.log(decompress(Buffer.from(claims.data, 'hex')))
})

emulator.on('signer-key-generated', (details) => {
  publicKey = details.publicKey
})

emulator.on('log', (event) => {
  console.log(`${event.datetime.toISOString()} [${event.level}] ${event.message} (+${event.timeSinceLast})`)
})

```