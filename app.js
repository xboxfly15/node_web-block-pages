'use strict'
const express = require('express')
const dns = require('dns')
const fs = require('fs')
const uuid = require('uuid')
const escape = require('escape-html')
const Transform = require('stream').Transform
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
  const app = express();
  app.disable('x-powered-by')
  app.disable('etag')

  app.use(function(req, res, next) {
    res.ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress).split(':').pop()
    res.ip = res.ip == '::1' ? 'privateIp' : res.ip
    res.ua = req.headers['user-agent']
    res.lang = req.headers['accept-language']
    res.referer = req.headers['referer']
    res.method = req.method
    res.host = req.get('host').split(':').shift();
    res.fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl
    res.setHeader('Content-Type', 'text/html')
    return next()
  });

  app.get(['/', '/*', '*'], (req, res) => {
    getIPFromURL(res.host).then(urlip => {
      const parser = new Transform()
      const blockid = uuid.v4()
      const current = new Date()
      parser._transform = function(data, encoding, done) {
        var str = data.toString()
        str = str.replace('{URL}', res.host)
        str = str.replace('{FULL_URL}', escape(res.fullUrl))
        str = str.replace('{URL_IP}', urlip)
        str = str.replace('{BLOCK_ID}', blockid)
        str = str.replace('{DATE}', current.toLocaleString())
        str = str.replace('{REQUEST_IP}', res.ip)
        str = str.replace('{REASON}', reason)
        str = str.replace('{USER_AGENT}', escape(res.ua))
        str = str.replace('{METHOD}', res.method)
        str = str.replace('{REFERER}', res.referer === undefined ? 'Unknown' : escape(res.referer))
        this.push(str)
        done()
      }
      res.status(451)
      const rs = fs.createReadStream(path)
      rs.on('error', err => {res.send();console.error(err)})
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
  const html = __dirname + '/public_html/'
  switch(reason) {
    case reasons.UNKNOWN:         return html+'unknown.html'
    case reasons.ADVERTISEMENTS:  return html+'advertisements.html'
    case reasons.BETTING:         return html+'betting.html'
    case reasons.VPNORPROXY:      return html+'vpnorproxy.html'
    case reasons.INAPPROPRATE:    return html+'inapproprate.html'
    case reasons.ILLEGAL:         return html+'illegal.html'
    case reasons.MALICIOUS:       return html+'malicious.html'
    case reasons.MALWARE:         return html+'malware.html'
    case reasons.PHISHING:        return html+'phishing.html'
    default: throw new Error('Reason is not defined')
  }
}

function getIPFromURL(url) {
  return new Promise((resolve, reject) => {
    dns.lookup(url, function(err, result) {
      if(err) throw reject(err);
      resolve(result)
    })
  })
}