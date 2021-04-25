const sun  = require("../sun")

const key = Buffer.from("00000000000000000000000000000000", 'hex')
let encryptedText = Buffer.from("4875ED0DA384F16DC932D021920E930B", 'hex')
console.log(sun.decryptPicc(encryptedText, key))

