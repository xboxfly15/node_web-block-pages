const dns = require('dns')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const escape = require('escape-html')
const { Transform } = require('stream')
const htmlFiles = 'public_html'
const reasons = {
  UNKNOWN: 'UNKNOWN',
  ADVERTISEMENTS: 'ADVERTISEMENTS',
  BETTING: 'BETTING',
  VPNORPROXY: 'VPN/PROXY',
  INAPPROPRATE: 'INAPPROPRATE',
  ILLEGAL: 'ILLEGAL',
  MALICIOUS: 'MALICIOUS',
  MALWARE: 'MALWARE',
  PHISHING: 'PHISHING'
}

console.log('Starting webservers...')
webserver(8560, reasons.UNKNOWN)
webserver(8561, reasons.ADVERTISEMENTS)
webserver(8562, reasons.BETTING)
webserver(8563, reasons.VPNORPROXY)
webserver(8564, reasons.INAPPROPRATE)
webserver(8565, reasons.ILLEGAL)
webserver(8566, reasons.MALICIOUS)
webserver(8567, reasons.MALWARE)
webserver(8568, reasons.PHISHING)

function webserver(port, reason) {
  const path = getPath(reason)
  const app = require('express')()

  app.use((req, res, next) => {
    res.setHeader('Content-Type', 'text/html')
    return next()
  })

  app.get(['/', '/*', '*'], (req, res) => {
    getIPFromURL(res.host).then(urlip => {
      const parser = new Transform()
      const blockid = crypto.randomUUID()
      const current = new Date()
      parser._transform = function(data, encoding, done) {
        let str = data.toString()
        str = str.replace('{URL}', req.get('Host'))
        str = str.replace('{FULL_URL}', escape(req.protocol + '://' + req.get('host') + req.originalUrl))
        str = str.replace('{URL_IP}', urlip)
        str = str.replace('{BLOCK_ID}', blockid)
        str = str.replace('{DATE}', current.toLocaleString())
        str = str.replace('{REQUEST_IP}', req.connection.remoteAddress)
        str = str.replace('{REASON}', reason)
        str = str.replace('{USER_AGENT}', escape(req.headers['user-agent']))
        str = str.replace('{METHOD}', req.method)
        str = str.replace('{REFERER}', req.referer === undefined ? 'Unknown' : escape(req.referer))
        this.push(str)
        done()
      }
      res.status(451)
      const rs = fs.createReadStream(path)
      rs.on('error', err => { res.send(); console.error(err) })
      rs.pipe(parser).pipe(res)
      console.log('New request {' +
        '\n   Date: ' + current +
        '\n   IP: ' + res.ip +
        '\n   User agent: ' + res.ua +
        '\n   Browser language: ' + res.lang +
        '\n   URL: ' + res.fullUrl +
        '\n   Returned Path: ' + path +
        '\n   HTTP Code: ' + 451 +
        '\n   URL IP: ' + urlip +
        '\n   Block ID: ' + blockid +
        '\n}'
      )
    }).catch(err => console.error(err))
  })
  app.listen(port, () => console.log('Webserver listening at port %s with path %s', port, path))
}

function getPath(reason) {
  switch (reason) {
    case reasons.UNKNOWN: return path.join(htmlFiles, 'unknown.html')
    case reasons.ADVERTISEMENTS: return path.join(htmlFiles, 'advertisements.html')
    case reasons.BETTING: return path.join(htmlFiles, 'betting.html')
    case reasons.VPNORPROXY: return path.join(htmlFiles, 'vpnorproxy.html')
    case reasons.INAPPROPRATE: return path.join(htmlFiles, 'inapproprate.html')
    case reasons.ILLEGAL: return path.join(htmlFiles, 'illegal.html')
    case reasons.MALICIOUS: return path.join(htmlFiles, 'malicious.html')
    case reasons.MALWARE: return path.join(htmlFiles, 'malware.html')
    case reasons.PHISHING: return path.join(htmlFiles, 'phishing.html')
    default: throw new Error('Reason is not defined')
  }
}

function getIPFromURL(url) {
  return new Promise((resolve, reject) => {
    dns.lookup(url, function(err, result) {
      if (err) throw reject(err)
      resolve(result)
    })
  })
}
