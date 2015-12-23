var store = require('./X509')
var cert = [];
store.forEach(function (info, index) {
    cert.push(info);
    console.log(index, info)
})
