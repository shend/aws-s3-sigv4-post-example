const crypto = require("crypto-js");

function getSignatureKey(Crypto, key, dateStamp, regionName, serviceName) {
    const kDate = Crypto.HmacSHA256(dateStamp, "AWS4" + key);
    const kRegion = Crypto.HmacSHA256(regionName, kDate);
    const kService = Crypto.HmacSHA256(serviceName, kRegion);
    return Crypto.HmacSHA256("aws4_request", kService);
}


let key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
let dateStamp = '20190426';
let regionName = 'us-east-1';
let serviceName = 's3';

let policy = { "expiration": "2019-04-27T12:00:00.000Z",
    "conditions": [
        ["starts-with", "$key", "user/user1/"],
        {"acl": "public-read"},
        ["starts-with", "$Content-Type", "image/"],
        {"x-amz-meta-uuid": "14365123651274"},
        ["starts-with", "$x-amz-meta-tag", ""],
        {"x-amz-credential": "AKIAIOSFODNN7EXAMPLE/20190426/us-east-1/s3/aws4_request"},
        {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
        {"x-amz-date": "20190426T000000Z" }
    ]
};

const  base64Policy = Buffer.from(JSON.stringify(policy), 'utf-8').toString('base64');

console.log('Policy Base64 String:');
console.log(base64Policy);
console.log('');

const signatureKey = getSignatureKey(crypto, key, dateStamp, regionName, serviceName);
const s3Signature = crypto.HmacSHA256(base64Policy, signatureKey).toString(crypto.enc.Hex);
console.log('X-Amz-Signature');
console.log(s3Signature);
