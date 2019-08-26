const send = require('./').send
const fs=require('fs')
const Http = require('./handlers/client/http.js').HttpClientHandler
const X509BinarySecurityToken = require('./handlers/client/security/security.js').X509BinarySecurityToken
const Signature = require('./handlers/client/security/signature.js').Signature
const Security = require('./handlers/client/security/security.js').SecurityClientHandler
const axios = require('axios')

class SoapClient {
    // ..and an (optional) custom class constructor. If one is
    // not supplied, a default constructor is used instead:
    // constructor() { }
    constructor(certificadoSOAP,options) {
 
        this.certificate ={
            private: fs.readFileSync(certificadoSOAP.privKey).toString(),
            public: fs.readFileSync(certificadoSOAP.pubKey).toString()
        }
        const x509 = new X509BinarySecurityToken({
          key: `${this.certificate.private}\n${this.certificate.public}`,
        })
        const signature = new Signature(x509)
        signature.addReference("//*[local-name(.)='Body']")
        signature.addReference("//*[local-name(.)='Timestamp']")
    
        this.http = new Http()
        this.security = new Security({}, [x509, signature])
        this.Mtom = new Mtom()
        this.handlers = [this.security, this.http]
        this.options=options
    }
    // Si requiere MTOM 
    setHandlers(handlers) {
        this.handlers = handlers
    }
    setMtom(mtom) {
      if (mtom)
        this.handlers = [this.security,this.Mtom, this.http]
    }
    setRequest(request) {
      this.request = request
    }
    getHttp(){
        return this.http
    }

    getSecurity(){
        return this.security
    }
 
    call (ctx,pCtx, logger) 
      {
      new Promise((resolve, reject) => {
        const newctx = {
            ...ctx,
          contentType: 'text/xml',
          cert: this.certificate.public,
          key: this.certificate.private,
        } 
        const shouldLog = this.options.log
        const logOperation = this.log
        const debug = this.options.debug
        const loggerEndPoint = this.options.loggerEndPoint
        const opData = {
          date: new Date().toISOString(),
          status: 'OK',
        } 
        send(this.handlers, newctx, (resctx) => {

          if (resctx.statusCode === 200) {
            if (debug) {
              if (logger){
                logger.debug(
                  `ClienteSoap:call:send:${
                    opData.status
                  }: Ctx=${JSON.stringify(
                    pCtx
                  )} - Request=${this.request?this.request:resctx.request} - Response=${resctx.response}`
                )
             }
            }
            if (shouldLog) {
              logOperation(pCtx, logger, opData, this.request?this.request:resctx.request, resctx.response,ctx.serviceName,loggerEndPoint).then(() => {
                resolve(resctx.response)
              })
            } else {
              resolve(resctx.response)
            }
          } else {
            opData.status='ERROR'
            if (debug) {
              if (logger){
                logger.debug(
                  `ClienteSoap:call:send:${
                    opData.status
                  }: Ctx=${JSON.stringify(
                    pCtx
                  )} - Request=${this.request?this.request:resctx.request} - Response=${resctx.response}`
                )
             }
            }
            if (shouldLog) {
              logOperation(pCtx, logger, opData, this.request?this.request:resctx.request, resctx.response,ctx.serviceName,loggerEndPoint).then(() => {
                reject(new Error(resctx.response))
              })
            } else {
              reject(new Error(resctx.response))
            }
          }
        })
      })
    }
    async log(
      ctx,
      logger,
      op,
      req,
      res,
      serviceName,
      loggerEP
    ){
      
      const logRequest = {
        consumer: {
          appConsumer: {
            id: ctx.consumer.appConsumer.id,
            sessionId: ctx.consumer.appConsumer.sessionId,
            transactionId: ctx.consumer.appConsumer.transaccionId,
          },
          deviceConsumer: {
            id: ctx.consumer.deviceConsumer.id,
            ip: ctx.ipAddress,
            locale: ctx.consumer.deviceConsumer.locale,
            terminalId: ctx.consumer.appConsumer.terminalId,
            userAgent: ctx.consumer.deviceConsumer.userAgent,
          },
        },
        documento: {
          numero: ctx.documento.numero,
          tipo: ctx.documento.tipo,
        },
        messages: {
          idService: serviceName,
          requestService: req,
          responseService: res || 'SIN-DATOS',
        },
        operation: {
          operationDate: op.date,
          statusResponse: {
            status: op.status,
          },
          type: ctx.type,
        },
      }
      try {
        await axios.post(loggerEP, logRequest)
      } catch (error) {
        logger.error(`ClienteSoap:call:logger error: ${error.message}`)
      }
    }
  }
exports.SoapClient=SoapClient