const crypto = require('crypto');

function generateEMVSignature() {
    // EMV test data (in order they appear in the packed format)
    const arqc = Buffer.from("1234567890ABCDEF", "hex");  // 8 bytes
    const unpredictableNumber = Buffer.from("12345678", "hex");  // 4 bytes  
    const atc = Buffer.from("0000", "hex");  // 2 bytes
    const amount = Buffer.from("000000010000", "hex");  // 6 bytes
    const currency = Buffer.from("0348", "hex");  // 2 bytes
    const date = Buffer.from("231201", "hex");  // 3 bytes
    const txnType = Buffer.from("00", "hex");  // 1 byte
    const tvr = Buffer.from("0000000000", "hex");  // 5 bytes
    const cvmResults = Buffer.from("000000", "hex");  // 3 bytes
    const terminalId = Buffer.from("5445535430303100", "hex");  // 8 bytes "TEST001" padded
    const merchantId = Buffer.from("4D45524348414E5430303132333400", "hex");  // 15 bytes "MERCHANT001234" padded
    const acquirerId = Buffer.from("414351554952", "hex");  // 6 bytes "ACQUIR"
    
    // Assemble all EMV fields (63 bytes total)
    const allFields = Buffer.concat([
        arqc, unpredictableNumber, atc, amount, currency,
        date, txnType, tvr, cvmResults, terminalId,
        merchantId, acquirerId
    ]);
    
    console.log(`All EMV fields length: ${allFields.length} bytes`);
    console.log(`All EMV fields hex: ${allFields.toString('hex')}`);
    
    // Create Signed Data Format 3 structure
    const header = Buffer.from("6A", "hex");
    const format = Buffer.from("03", "hex");
    const trailer = Buffer.from("BC", "hex");
    
    const dynamicData = Buffer.concat([header, format, allFields, trailer]);
    console.log(`Dynamic data length: ${dynamicData.length} bytes`);
    console.log(`Dynamic data hex: ${dynamicData.toString('hex')}`);
    
    // Generate new RSA key pair (2048-bit for testing)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'der'
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'der'
        }
    });
    
    // Create SHA-256 hash and sign using PKCS#1 v1.5
    const signature = crypto.sign('sha256', dynamicData, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    });
    
    console.log(`Signature length: ${signature.length} bytes`);
    console.log(`Signature hex: ${signature.toString('hex')}`);
    
    // Extract public key components from DER encoded key
    // For now, let's create a simplified version - we'll use the key as-is
    // and extract modulus/exponent manually from the DER structure
    
    // Parse the DER-encoded public key to extract modulus and exponent
    // This is a simplified extraction - in practice you'd use a proper ASN.1 parser
    const pubKeyBuffer = publicKey;
    
    // For RSA public keys in SPKI format, the modulus typically starts after some header bytes
    // and the exponent is usually 0x010001 (65537)
    // Let's find the modulus (256 bytes for 2048-bit key)
    
    // Since we can't easily parse DER without additional libraries,
    // let's use the crypto.verify to check our signature works
    const isValid = crypto.verify('sha256', dynamicData, {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, signature);
    
    console.log(`Signature verification: ${isValid}`);
    
    // For the test, we'll extract modulus and exponent differently
    // Let's create a simpler approach with known test values
    
    // Use a fixed test key pair for consistency
    const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4bsRsTQozs6hOSBhKhgFM7FzMXJtFyBVYP7/i9VmVQz8+b7Z
ZGYHkS9LX3VKyE5vkS0tNF6B4QUKrM2Vr1X4X5X5X5X5X5X5X5X5X5X5X5X5X5X
5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5
X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X
5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5
X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X
5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5
X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X
5wIDAQABAoIBAF8i7s6K8EXAMPLE_PRIVATE_KEY_CONTENT_HERE
-----END RSA PRIVATE KEY-----`;

    // For testing purposes, let's just output what we have and create a simple test case
    return {
        dynamicData: dynamicData.toString('hex'),
        signature: signature.toString('hex'),
        allFields: allFields.toString('hex'),
        isValid: isValid
    };
}

// Since we need consistent test data, let's manually create the values
function createConsistentTestData() {
    // Use the existing test modulus from the Solidity test for consistency
    const existingModulus = "e1bb031f4389e26a6d2fb1eab48946263b9386667aca2a10c71fd2a81ecc76e27de78698819f86339207b24fa69b9e2cefc6db2d68f102d773b4d1e2b4d7f7c0ddbaed43b3c09ef094a1aa17873ee52542a6fa4e096744659bedbd41931739e2993dccfbd3fcc58dcfc6db5a27affc9020b38015086b4cb91829d55102f72d5b282769ff2618d168ea7c5ef3f200c69033e2e23e835617e5b86ecbadc9ff19782c5e679e35371d169ea64a8371c9a89acc50eb6f6a0851038ee725d93da77e981a1d0327d3c557253a533629cd2bf21c476a4001c76e6985902655c68a6951e74f071087c7be29bda5e25b8943c4f55eafbbbbc8beea975a746908b94b66c917";
    const existingExponent = "010001";
    
    // Calculate the new expected dynamic data with 63 bytes
    const allFields = "1234567890abcdef123456780000000000010000034823120100000000000000000054455354303031004d45524348414e5430303132333400414351554952";
    const dynamicData = "6a03" + allFields + "bc";
    
    console.log("\n=== Updated test constants ===");
    console.log(`All EMV fields (63 bytes): ${allFields}`);
    console.log(`Expected dynamic data: ${dynamicData}`);
    console.log(`Dynamic data length: ${Buffer.from(dynamicData, 'hex').length} bytes`);
    
    // For the signature, we'll need to create a dummy one since we don't have the private key
    // The test will need to be updated to either skip signature verification or use a known key pair
    const dummySignature = "0".repeat(512); // 256 bytes of zeros for now
    
    console.log("\n=== Constants for Solidity test ===");
    console.log(`bytes constant EXPECTED_DYNAMIC_DATA = hex"${dynamicData}";`);
    console.log(`// NOTE: TEST_SIGNATURE needs to be regenerated with a known private key`);
    console.log(`// or the test should be modified to use a mock verification`);
}

if (require.main === module) {
    try {
        const result = generateEMVSignature();
        console.log('\nGenerated signature validation:', result.isValid);
    } catch (error) {
        console.log('Error generating signature:', error.message);
    }
    
    // Always create the consistent test data
    createConsistentTestData();
}
