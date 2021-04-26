// Nodejs encryption with CTR
const crypto = require('crypto')
const aesCmac = require('node-aes-cmac').aesCmac

function calculateCmacData(uid, readCnt, key) {
    let piccData = Buffer.alloc(10);
    Buffer.from(uid, 'hex').copy(piccData);
    piccData.writeIntLE(readCnt, 7, 3);
    return calculateCmacBuffer(piccData, key)
}

function calculateCmacBuffer(piccData, key) {
    let sv2Data = Buffer.alloc(16);
    sv2Data.write('3CC300010080', 'hex') // SV2 as per NXP DS465430 (NT4H2421Gx Data sheet)
    piccData.copy(sv2Data, 6);
    let sv2 = aesCmac(key, sv2Data, {returnAsBuffer: true});
    let fullCmac = aesCmac(sv2, Buffer.alloc(0), {returnAsBuffer: true});
    let cmac = Buffer.alloc(8);
    for (let i = 0; i < 8; i++) {
        fullCmac.copy(cmac, i, i*2+1, i*2+2);
    }
    return cmac
}

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

module.exports = {
    calculateCmacData,
    calculateCmacBuffer,
    decryptPicc
}