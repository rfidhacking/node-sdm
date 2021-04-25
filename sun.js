// Nodejs encryption with CTR
const crypto = require('crypto')



function decryptPicc(PICCENCData, key) {
    let decipher = crypto.createDecipheriv('aes-128-cbc', key, Buffer.alloc(16))
    decipher.setAutoPadding(false)
    let decrypted = decipher.update(PICCENCData)
    tagPicc = Buffer.concat([decrypted, decipher.final()])


    return {
        PICC_DataTag: tagPicc.slice(0, 1).toString("hex"),
        uid: tagPicc.slice(1, 8).toString("hex"),
        cnt: tagPicc.slice(8, 11).toString("hex"),
        cntInt: tagPicc.readUIntLE(8, 3)
    }
}

module.exports.decryptPicc=decryptPicc