const send = require('./').send
const fs=require('fs')
const Http = require('./handlers/client/http.js').HttpClientHandler
const X509BinarySecurityToken = require('./handlers/client/security/security.js').X509BinarySecurityToken
const Signature = require('./handlers/client/security/signature.js').Signature
const Security = require('./handlers/client/security/security.js').SecurityClientHandler


class SoapClient {
    // ..and an (optional) custom class constructor. If one is
    // not supplied, a default constructor is used instead:
    // constructor() { }
    constructor(certificadoSOAP) {
 
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
        this.handlers = [this.security, this.http]

    }
    // Si requiere MTOM 
    setHandlers(handlers) {
      this.handlers = handlers
    }
    getHttp(){
        return this.http
    }

    getSecurity(){
        return this.security
    }
 
    call (ctx, logger) 
      {
      new Promise((resolve, reject) => {
        const newctx = {
            ...ctx,
          contentType: 'text/xml',
          cert: this.certificate.public,
          key: this.certificate.private,
        }  
        send(this.handlers, newctx, (resctx) => {
          if (logger){  
              logger.debug(
              `Biometria-Service:AutenticacionDactilar:SendAC > Response: ${JSON.stringify(
                  resctx.response
              )}`
              
              )
          }
          if (resctx.statusCode === 200) {
            resolve(resctx.response)
          } else {
            reject(new Error(resctx.response))
          }
        })
      })
    }
  }
exports.SoapClient=SoapClient