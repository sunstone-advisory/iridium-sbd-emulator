/* eslint-disable no-unused-vars */
import fs from 'fs'
import jwt from 'jsonwebtoken'
import { SerialPort } from 'serialport'
import { generateKeyPair } from 'crypto'
import { TypedEmitter } from 'tiny-typed-emitter'
import { ReadlineParser } from '@serialport/parser-readline'
import { InterByteTimeoutParser } from '@serialport/parser-inter-byte-timeout'

import { delay, randomInterval } from './utils'

const MILLISECOND = 1
const SECOND = MILLISECOND * 1000
const MINUTE = SECOND * 60
const HOUR = MINUTE * 60
const SIMPLE_WAIT_TIME = randomInterval(10 * MILLISECOND, 50 * MILLISECOND)
const LONG_WAIT_TIME = randomInterval(15 * SECOND, 30 * SECOND)

export enum SignalQualityRating {
  NONE,
  POOR,
  OK,
  GOOD,
  EXCELLENT,
  RANDOM
}

export enum SignalQuality {
  NONE = 0,
  ONE = 1,
  TWO = 2,
  THREE = 3,
  FOUR = 4,
  FIVE = 5
}

// snake case to match rock7 service provider
export type SBDMessage = {
  momsn: number
  data: string
  serial: number
  'iridium_latitude': number
  'iridium_longitude': number
  'iridium_cep': number
  imei: string
  'device_type': string
  'transmit_time': string
  JWT: string
}

export type JWTSignerDetails = {
  publicKey: string
  privateKey: string
  passphrase: string
}

export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  CRITICAL = 'CRITICAL'
}

export type LogEvent = {
  level: LogLevel
  message: string
  datetime: Date
  timeSinceLast: string
}

export interface IridiumEmulatorInterface {
  'log': (event: LogEvent) => void
  'sbd-message': (message: SBDMessage) => void
  'signer-key-generated': (details: JWTSignerDetails) => void
}

export class IridiumEmulator extends TypedEmitter<IridiumEmulatorInterface> {
  /** The virtual serial port connection */
  #port: SerialPort

  get port () {
    return this.#port
  }

  /** Indicates if the inbound command should be echo'd back on the port */
  #echoEnabled = true

  get echoEnabled () {
    return this.#echoEnabled
  }

  /** Indicates if responses should be sent to the DTE */
  #quietMode = false

  get quietMode () {
    return this.#quietMode
  }

  /** Indicates that the device is no longer responding to commands and is ready to be powered down */
  #readyForShutdown = false

  get readyForShutdown () {
    return this.#readyForShutdown
  }

  /** Indicates if radio activty is enabled (must be enabled for SDBI[XA] sessions) */
  #radioActivityEnabled = true

  get radioActivityEnabled () {
    return this.#radioActivityEnabled
  }

  /** Indicates if ring alerts is enabled on the emulator */
  #ringAlertsEnabled = false

  get ringAlertsEnabled () {
    return this.#ringAlertsEnabled
  }

  /** Indicates if there is an active ring alert waiting to be answered */
  #ringAlertActive = false

  get ringAlertActive () {
    return this.#ringAlertActive
  }

  /** The quality of signal the emulator should mock */
  #signalQualityRating: SignalQualityRating = SignalQualityRating.OK

  get signalQualityRating () {
    return this.#signalQualityRating
  }

  /** The current signal quality of the emulator */
  #currentSignalQuality: SignalQuality = SignalQuality.ONE

  get currentSignalQuality () {
    return this.#currentSignalQuality
  }

  /** Indicates if signal quality indicator is enabled on the emulator */
  #signalQualityIndicator = false

  get signalQualityIndicator () {
    return this.#signalQualityIndicator
  }

  /** Indicates if the service availability indicator is enabled on the emulator */
  #serviceAvailabilityIndicator = false

  get serviceAvailabilityIndicator () {
    return this.#serviceAvailabilityIndicator
  }

  /** The current buffer for Mobile Orientated (MO) messages */
  #moBuffer: Buffer

  get moBuffer () {
    return this.#moBuffer
  }

  /* The sequence number for Mobile Orientated (MO) messages */
  #moSequenceNo = 0

  get moSequenceNo () {
    return this.#moSequenceNo
  }

  /** The current buffer for Mobile Terminated (MT) messages */
  #mtBuffer: string

  get mtBuffer () {
    return this.#mtBuffer
  }

  /* The sequence number for Mobile Terminated (MT) messages */
  #mtSequenceNo = 0

  get mtSequenceNo () {
    return this.#mtSequenceNo
  }

  /** Indicates that incoming data is expected to be binary and appended to buffer */
  #binaryMode = false

  get binaryMode () {
    return this.#binaryMode
  }

  /** Buffer containing the inbound binary data */
  #binaryBuffer: Buffer | null

  get binaryBuffer () {
    return this.#binaryBuffer
  }

  /** The expected length of the inbound binary data */
  #binaryBufferLength: number

  get binaryBufferLength () {
    return this.#binaryBufferLength
  }

  /** Timeout function to invoke when binary data is not received */
  #binaryBufferTimeout: NodeJS.Timeout | null

  get binaryBufferTimeout () {
    return this.#binaryBufferTimeout
  }

  /* The software revision level of the module */
  #softwareRevisionLevel = 'TA20003'

  get softwareRevisionLevel () {
    return this.#softwareRevisionLevel
  }

  /* The product description of the module */
  #productDescription = 'IRIDIUM 9600 Family'

  get productDescription () {
    return this.#productDescription
  }

  /* Model number of the module */
  #deviceModel = 'IRIDIUM 9600 Family SBD Transceiver'

  get deviceModel () {
    return this.#deviceModel
  }

  /* Serial number of the module */
  #serialNumber = '10000000000000'

  get serialNumber () {
    return this.#serialNumber
  }

  /* The hardware specification of the module */
  #hardwareSpecification = 'BOOT07d4/9603NrevDE/04/RAW0c'

  get hardwareSpecification () {
    return this.#hardwareSpecification
  }

  /** The JWT signer key which is used to sign outbound messages */
  #jwtSignerKey: string

  /** The passphrase required to unencrypt the jwtSignerKey */
  #jwtSignerKeyPassphrase: string

  /** Serial port parser to read input based on new line delimeter */
  #readlineParser: ReadlineParser

  /** Serial port parser to read input based on binary */
  #binaryParser: InterByteTimeoutParser

  constructor ({
    portPath,
    baudRate = 19200,
    signalQualityRating = SignalQualityRating.OK,
    jwtSignerKey,
    jwtSignerKeyPassphrase
  }: {
    portPath: string,
    baudRate?: number,
    signalQualityRating: SignalQualityRating,
    jwtSignerKey?: string,
    jwtSignerKeyPassphrase?: string
  }) {
    super()

    this.#port = new SerialPort({
      path: portPath,
      baudRate: baudRate
    })

    this.#port.on('open', () => {
      this.#logger.info('Serial port open')
    })

    this.#readlineParser = new ReadlineParser({ delimiter: '\r\n' })
    this.#readlineParser.on('data', async (data: string) => {
      await this.#handleData(data)
    })

    this.#binaryParser = new InterByteTimeoutParser({ interval: 30 })
    this.#binaryParser.on('data', async (data) => {
      await this.#handleData(data)
    })

    this.#port.pipe(this.#readlineParser)

    this.#moBuffer = Buffer.alloc(340)
    this.#mtBuffer = '' // TODO: COnvert to buffer
    this.#binaryBuffer = null
    this.#binaryBufferLength = 0
    this.#binaryBufferTimeout = null

    if (jwtSignerKey) {
      this.#jwtSignerKey = fs.readFileSync(jwtSignerKey).toString()

      if (jwtSignerKeyPassphrase) this.#jwtSignerKeyPassphrase = jwtSignerKeyPassphrase
    } else {
      // no key provided, generate a public/private key pair with random password
      const passphrase = Math.random().toString(36).slice(-8)

      generateKeyPair('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
          cipher: 'aes-256-cbc',
          passphrase
        }
      }, (error, publicKey, privateKey) => {
        if (error) throw error

        this.#jwtSignerKey = privateKey
        this.#jwtSignerKeyPassphrase = passphrase

        // notify the new public/private key pair
        this.emit('signer-key-generated', {
          publicKey,
          privateKey,
          passphrase
        })
      })
    }

    this.#signalQualityRating = signalQualityRating
    this.#updateSignalQuality()
  }

  #logger = {
    lastLogDateTime: new Date(),
    debug: (message: string) => this.#logger.log(LogLevel.DEBUG, message),
    info: (message: string) => this.#logger.log(LogLevel.INFO, message),
    warn: (message: string) => this.#logger.log(LogLevel.WARN, message),
    error: (message: string) => this.#logger.log(LogLevel.ERROR, message),
    critical: (message: string) => this.#logger.log(LogLevel.CRITICAL, message),
    log: (level: LogLevel, message: string) => {
      const datetime = new Date()

      const difference = new Date().getTime() - this.#logger.lastLogDateTime.getTime()
      let timeSinceLast

      if (difference > HOUR) {
        timeSinceLast = Math.round(difference / HOUR) + 'h'
      } if (difference > MINUTE) {
        timeSinceLast = Math.round(difference / MINUTE) + 'm'
      } else if (difference > SECOND) {
        timeSinceLast = Math.round(difference / SECOND) + 's'
      } else {
        timeSinceLast = difference + 'ms'
      }

      this.emit('log', { level, datetime, message, timeSinceLast })

      this.#logger.lastLogDateTime = datetime
    }
  }

  #write (data: string): void {
    this.#logger.info(`>> ${data}`)
    if (!this.quietMode) {
      this.#port.write(data + '\r\n')
    }
  }

  #toggleBinaryMode = (binaryBufferLength?: number): void => {
    if (this.#binaryBufferTimeout !== null) clearTimeout(this.#binaryBufferTimeout)

    this.#binaryMode = !this.#binaryMode
    this.#binaryBufferLength = binaryBufferLength ?? 0
    this.#binaryBuffer = null

    if (this.#binaryMode) {
      this.#binaryBufferTimeout = setTimeout(() => {
        this.#logger.warn('SBD message write timeout. An insufficient number of bytes were transferred to 9602 during the transfer period of 60 seconds')
        this.#write('1')
        this.#toggleBinaryMode()
      }, 60 * SECOND)

      this.#port.unpipe(this.#readlineParser)
      this.#port.pipe(this.#binaryParser)

      this.#write('READY')
    } else {
      this.#port.unpipe(this.#binaryParser)
      this.#port.pipe(this.#readlineParser)
    }
  }

  #handleData = async (data: string | Buffer): Promise<void> => {
    this.#logger.info(`<< ${this.#binaryMode ? data.toString('hex') : data}`)

    if (this.#binaryMode) {
      try {
        const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data, 'hex')
        this.#binaryBuffer = this.#binaryBuffer ? Buffer.concat([this.#binaryBuffer, chunk]) : chunk
      } catch (error: any) {
        this.#logger.error('Buffer overload. ' + error.message ?? '')
        this.#write('2')
        return this.#toggleBinaryMode()
      }

      if (this.#binaryBuffer.length === this.#binaryBufferLength) {
        // received the expected number of bytes, now we can
        // calculate the checksum against the checksum provided
        // by the client.
        const buffer = this.#binaryBuffer.subarray(0, this.#binaryBuffer.length - 2)
        const checksum = this.#binaryBuffer.subarray(this.#binaryBuffer.length - 2, this.#binaryBuffer.length)

        let sum = 0
        for (let i = 0; i < buffer.length; i++) sum += buffer[i]

        const calculatedChecksum = Buffer.alloc(2)

        // set the least significant byte of the message summation
        calculatedChecksum[1] = sum & 0xff

        // drop the least significant byte
        sum >>= 8

        // set the (second) least significant byte of the message summation
        calculatedChecksum[0] = sum & 0xff

        this.#logger.debug(`Client provided checksum was '${checksum.toString('hex')}', calculated checksum was '${calculatedChecksum.toString('hex')}'`)

        if (checksum.equals(calculatedChecksum)) {
          this.moBuffer.fill(0x00)
          buffer.copy(this.#moBuffer)
          this.#write('0')
        } else {
          this.#logger.warn('SBD message checksum sent from DTE does not match the checksum calculated by the 9602.')
          this.#write('2')
        }

        this.#toggleBinaryMode()
      } else if (this.#binaryBuffer.length > this.#binaryBufferLength) {
        this.#logger.warn(`Received more binary data (${this.#binaryBuffer.length}) than expected (${this.#binaryBufferLength})`)
        this.#write('2')

        this.#toggleBinaryMode()
      }

      return
    }

    // we are no longer processing commands...
    if (this.#readyForShutdown) return

    if (data instanceof Buffer) {
      this.#write('ERROR')
      return
    }

    let command, detail

    if (data.includes('=')) {
      command = data.substring(0, data.indexOf('=') + 1)
      detail = data.substring(data.indexOf('=') + 1, data.length)
    } else {
      command = data
    }

    if (this.#echoEnabled) {
      await delay(SIMPLE_WAIT_TIME)
      this.#write(data)
    }

    await delay(SIMPLE_WAIT_TIME)

    switch (command) {
      /** Disable DTE Echo */
      case 'ATE0':
        this.#echoEnabled = false
        this.#write('OK')
        break

      /** Enable DTE Echo */
      case 'ATE1':
        this.#echoEnabled = true
        this.#write('OK')
        break

      /** Identification - Compatability */
      case 'ATI0':
        this.#write('2400')
        this.#write('OK')
        break

      /** Identification - Compatability */
      case 'ATI1':
        this.#write('0000')
        this.#write('OK')
        break

      /** Identification - Compatability */
      case 'ATI2':
        this.#write('OK')
        this.#write('OK')
        break

      /** Identification - Software Revision Level */
      case 'ATI3':
        this.#write(this.#softwareRevisionLevel)
        this.#write('OK')
        break

      /** Identification - Product Description */
      case 'ATI4':
        this.#write(this.#productDescription)
        this.#write('OK')
        break

      /** Identification - Compatability */
      case 'ATI5':
        this.#write('8861')
        this.#write('OK')
        break

      /** Identification - Factory Identity */
      case 'ATI6':
        this.#write('16E')
        this.#write('OK')
        break

      /** Identification - Hardware Specification */
      case 'ATI7':
        this.#write(this.hardwareSpecification)
        this.#write('OK')
        break

      /** Quiet Mode - Disable */
      case 'ATQ0':
        this.#quietMode = false
        this.#write('OK')
        break

      /** Quiet Mode - Enable */
      case 'ATQ1':
        this.#quietMode = true
        this.#write('OK')
        break

      /** Verbose Mode - Disable */
      case 'ATV0':
        // not supported
        this.#write('ERROR')
        break

      /** Verbose Mode - Enable */
      case 'ATV1':
        this.#write('OK')
        break

      /** Restore User Config */
      case 'ATZ0': // Profile 0
      case 'ATZ1': // Profile 1
        this.#write('OK')
        break

      /** Restore Factory Settings */
      case 'AT&F0':
        this.#write('OK')
        break

      /** Flow Control */
      case 'AT&K0': // Disable
      case 'AT&K3': // Enable
        this.#write('OK')
        break

      /** View Active and Stored Configuration */
      case 'AT&V':
        this.#write('ACTIVE PROFILE: ')
        this.#write('E0 Q0 V1 &D2 &K0')
        this.#write('S000:013 S004:010 S005:008 S013:049 S014:168 S021:048 S013:012 S039:000')
        this.#write('STORED PROFILE 0:')
        this.#write('E0 Q0 V1 &D2 &K0')
        this.#write('S000:013 S004:010 S005:008 S013:049 S014:168 S021:048 S013:012 S039:000')
        this.#write('STORED PROFILE 1:')
        this.#write('E0 Q0 V1 &D2 &K0')
        this.#write('S000:013 S004:010 S005:008 S013:049 S014:168 S021:048 S013:012 S039:000')
        this.#write('OK')
        break

      /** Store Active Configuration */
      case 'AT&W0': // Profile 0
      case 'AT&W1': // Profile 1
        this.#write('OK')
        break

      /** Designate Default Reset Profile */
      case 'AT&Y0': // Profile 0
      case 'AT&Y1': // Profile 1
        this.#write('OK')
        break

      /** Display Registers */
      case 'AT%R':
        this.#write('REG  DEC HEX  REG  DEC HEX')
        for (let i = 0; i < 128; i += 2) {
          await delay(SIMPLE_WAIT_TIME)
          this.#write('')
          this.#write(`S${String(i).padStart(3, '0')} 000 00H  S${String(i + 1).padStart(3, '0')} 000 00H`)
        }
        this.#write('OK')
        break

      /** Flush to EEPROM */
      case 'AT*F':
        this.#readyForShutdown = true
        this.#quietMode = true
        break

      /** Radio Activity - Disable */
      case 'AT*R0':
        this.#radioActivityEnabled = false
        this.#write('OK')
        break

      /** Radio Activity - Enable */
      case 'AT*R1':
        this.#radioActivityEnabled = true
        this.#write('OK')
        break

      /** Real Clock Time */
      case 'AT+CCLK':
        // TODO: Better support for this
        this.#write('ERROR')
        break

      /** Manufacturer Identification */
      case 'AT+GMI':
      case 'AT+CGMI':
        this.#write('Iridium')
        this.#write('OK')
        break

      /** Model Identification */
      case 'AT+GMM':
      case 'AT+CGMM':
        this.#write(this.#deviceModel)
        this.#write('OK')
        break

      /** Revision Identification */
      case 'AT+GMR':
      case 'AT+CGMR':
        this.#write(`Call Processor Version: ${this.#softwareRevisionLevel}`)
        this.#write('')
        this.#write('Modem DSP Version: 1.7 sv: 4343')
        this.#write('')
        this.#write('DBB Version: 0x0001 (ASIC)')
        this.#write('')
        this.#write('RFA Version: 0x0007 (SRFA2)')
        this.#write('')
        this.#write('NVM Version: KVS')
        this.#write('')
        this.#write(`Hardware Version: ${this.hardwareSpecification}`)
        this.#write('')
        this.#write('BOOT Verson: 2004 TD2-BLB960X-27 R4710')
        this.#write('')
        this.#write('OK')
        break

      /** Serial Number Identification */
      case 'AT+GSN':
      case 'AT+CGSN':
        this.#write(this.#serialNumber)
        this.#write('OK')
        break

      /** Indicator Event Reporting */
      case 'AT+CIER=':
        switch (detail) {
          case '0,0,0,0': // Disable
          case '0,1,0,0': // Disable
          case '0,0,1,0': // Disable
          case '1,0,0,0': // Disable
            this.#serviceAvailabilityIndicator = false
            this.#signalQualityIndicator = false
            break
          case '1,1,0,0': // Enable Signal
            this.#signalQualityIndicator = true
            this.#serviceAvailabilityIndicator = false
            break
          case '1,0,1,0': // Enable Service
            this.#signalQualityIndicator = false
            this.#serviceAvailabilityIndicator = true
            break
          case '1,1,1,0': // Enable Signal & Service
            this.#signalQualityIndicator = true
            this.#serviceAvailabilityIndicator = true
            break
          default:
            this.#write('ERROR')
            return
        }

        this.#write('OK')

        if (this.#signalQualityIndicator) this.#write(`+CIEV:0,${this.#currentSignalQuality}`)
        if (this.#serviceAvailabilityIndicator) this.#write(`+CIEV:1,${this.#currentSignalQuality >= 1 ? 1 : 0}`)

        break

      /** Ring Indication Status */
      case 'AT+CRIS':
        this.#write(`+CRIS:${this.ringAlertActive ? '1' : '0'}`)
        this.#write('OK')
        break

      /** Signal Quality */
      case 'AT+CSQ':
        await delay(2 * SECOND)
        this.#write(`+CSQ:${this.signalQualityRating}`)
        this.#write('OK')
        break

      /** Signal Quality - Fast (Last Known) */
      case 'AT+CSQF':
        this.#write(`+CSQF:${this.signalQualityRating}`)
        this.#write('OK')
        break

      /** Unlock Device */
      case 'AT+CULK':
        // TODO: Better support for this
        this.#write('OK')
        break

      /** Unlock Device - Status */
      case 'AT+CULK?':
        // TODO: Better support for this
        this.#write('0')
        this.#write('OK')
        break

      /** Fixed DTE Rate */
      case 'AT+IPR':
        this.#write('OK')
        break

      /** Short Burst Data: Write a Text Message to the Module */
      case 'AT+SBDWT=':
        // TODO: Support for this command
        break

      /** Short Burst Data: Read a Text Message from the Module */
      case 'AT+SBDRT':
        this.#write('+SBDRT:')
        this.#write(this.#mtBuffer)
        this.#write('OK')
        break

      /** Short Burst Data: Write Binary Data to the ISU */
      case 'AT+SBDWB=': {
        let length = 0
        try {
          // attempt to parse expected binary length as integer
          length = parseInt(detail ?? '')
        } catch (error) {
          this.#write('ERROR')
          break
        }

        if (length < 1 || length > 340) {
          this.#logger.warn('SBD message size is not correct. The maximum mobile originated SBD message length is 340 bytes. The minimum mobile originated SBD message length is 1 byte')
          this.#write('3')
          break
        }

        this.#toggleBinaryMode(length + 2)
        break
      }

      /* Short Burst Data: Initiate an SBD Session Extended */
      case 'AT+SBDIX':
      case 'AT+SBDIXA': {
        const waitTime = LONG_WAIT_TIME

        if (!this.radioActivityEnabled) {
          this.#logger.warn('Radio activity is currently disabled. Unable to initiate simulated SBD session.')
          this.#write(`+SBDIX: 34, ${this.#moSequenceNo}, 2, ${this.#mtSequenceNo}, 0, 0`)
          this.#write('OK')
          break
        }

        this.#logger.debug(`Initiating simulated SBD session. Waiting ${Math.round(waitTime / SECOND)} seconds...`)

        await delay(waitTime)

        // the connection was successful if we still have 2 or more
        // bars of signal. if we have 1 bar of signal then it should
        // be a success 20% of the time.
        const success = this.#currentSignalQuality >= 2 ||
          (this.#currentSignalQuality === 1 && randomInterval(5, 10) % 10)

        if (success) {
          this.#moSequenceNo++
          this.#mtSequenceNo++

          // match the rock7 service provider datetime format
          let rbDateFormat = new Date().toISOString()
            .substring(2) // drop century
            .replace('T', ' ') // drop time indicator
            .replace('Z', '') // drop UTC timezone
          rbDateFormat = rbDateFormat
            .substring(0, rbDateFormat.length - 4) // drop milliseconds

          let index = 0
          for (let i = this.moBuffer.length - 1; i >= 0; i--) {
            if (this.moBuffer[i] === 0x00) continue
            index = i
            break
          }

          this.#logger.debug('Emitting sbd-message event with message details')
          const claims = {
            momsn: this.#moSequenceNo,
            data: this.moBuffer.slice(0, index + 1).toString('hex'),
            serial: 206899,
            iridium_latitude: 50.2563,
            iridium_longitude: 82.2532,
            iridium_cep: 122,
            imei: '300534062390910',
            device_type: 'ROCKBLOCK',
            transmit_time: rbDateFormat
          }

          // sign the claims and send the message
          const token = jwt.sign(claims, {
            key: this.#jwtSignerKey,
            ...this.#jwtSignerKeyPassphrase && {
              passphrase: this.#jwtSignerKeyPassphrase
            }
          }, {
            algorithm: 'RS256',
            issuer: 'Rock 7'
          })

          this.emit('sbd-message', {
            ...claims,
            JWT: token
          })
        }

        this.#write(`+SBDIX: ${success ? 0 : 32}, ${this.#moSequenceNo}, ${success ? 0 : 2}, ${this.#mtSequenceNo}, 0, 0`)
        this.#write('OK')

        break
      }

      /** Short Burst Data: Detatch */
      case 'AT+SBDDET':
        // TODO: Support for this command
        this.#write('+SBDDET:0,0')
        this.#write('OK')
        break

      /** Short Burst Data: Mobile-Terminated Alert */
      case 'AT+SBDMTA=':
        switch (detail) {
          case '0': // Disable SBD Ring Alert indication
            this.#ringAlertsEnabled = false
            this.#write('OK')
            break
          case '1': // Enable SBD Ring Alert indication (default)
            this.#ringAlertsEnabled = true
            this.#write('OK')
            break
          default:
            this.#write('ERROR')
        }
        break

      /** Short Burst Data: Automatic Registration */
      case 'AT+SBDAREG=':
        switch (detail) {
          case '0': // Disable Automatic SBD Network Registration (default)
          case '1': // Set the Automatic SBD Network Registration mode to "Automatic"
          case '2': // Set the Automatic SBD Network Registration mode to "Ask"
            this.#write('OK')
            break
          default:
            this.#write('ERROR')
        }
        break

      /** Short Burst Data: Clear SBD Message Buffer(s) */
      case 'AT+SBDD0':
        this.#moBuffer.fill(0)
        this.#write('OK')
        break
      case 'AT+SBDD1':
        this.#mtBuffer = ''
        this.#write('OK')
        break
      case 'AT+SBDD2':
        this.#moBuffer.fill(0)
        this.#mtBuffer = ''
        this.#write('OK')
        break

      default:
        this.#logger.error('Command not supported in emulator')
        this.#write('ERROR')
        break
    }
  }

  /**
   * Randomly updates the signal quality depending on
   * the configured network quality rating. The signal
   * quality will be updated at random intervals, as
   * specified in the configuration.
   */
  #updateSignalQuality = (): void => {
    let minSignalQuality, maxSignalQuality

    switch (this.#signalQualityRating) {
      case SignalQualityRating.NONE:
        minSignalQuality = SignalQuality.NONE
        maxSignalQuality = SignalQuality.NONE
        break
      case SignalQualityRating.POOR:
        minSignalQuality = SignalQuality.NONE
        maxSignalQuality = SignalQuality.TWO
        break
      case SignalQualityRating.OK:
        minSignalQuality = SignalQuality.ONE
        maxSignalQuality = SignalQuality.TWO
        break
      case SignalQualityRating.GOOD:
        minSignalQuality = SignalQuality.THREE
        maxSignalQuality = SignalQuality.FOUR
        break
      case SignalQualityRating.EXCELLENT:
        minSignalQuality = SignalQuality.FIVE
        maxSignalQuality = SignalQuality.FIVE
        break
      case SignalQualityRating.RANDOM:
        minSignalQuality = SignalQuality.NONE
        maxSignalQuality = SignalQuality.FIVE
    }

    if (!this.radioActivityEnabled) {
      minSignalQuality = SignalQuality.NONE
      maxSignalQuality = SignalQuality.NONE
    }

    const current = this.#currentSignalQuality
    const update = randomInterval(minSignalQuality, maxSignalQuality) as SignalQuality

    if (current !== update) {
      this.#currentSignalQuality = update
      this.#logger.debug(`Updated signal quality to '${update}'`)

      if (this.#signalQualityIndicator) this.#write(`+CIEV:0,${update}`)
      if (this.#serviceAvailabilityIndicator) this.#write(`+CIEV:1,${update >= 1 ? 1 : 0}`)
    } else {
      this.#logger.debug(`Signal quality remains as ${current}`)
    }

    const waitTime = randomInterval(15 * SECOND, 1 * MINUTE)
    this.#logger.debug(`Next signal quality update tick is in ${waitTime}ms`)

    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const _this = this

    setTimeout(function () {
      _this.#updateSignalQuality()
    }, waitTime)
  }
}
