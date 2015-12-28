var store = require('./X509')
var cert = [];
store.forEach(function (info, index) {
    cert.push(info);
    console.log(index, info)
})
// String.fromCharCode.apply(null, new Int8Array(a))