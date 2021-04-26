const sun  = require("../sun");

const key = Buffer.from("00000000000000000000000000000000", "hex");
const encryptedText = Buffer.from("EF963FF7828658A599F3041510671E88", "hex");

const data = sun.decryptPicc(encryptedText, key);

console.log(data);
console.log(sun.calculateCmacData(data.uid, data.cntInt, key));
