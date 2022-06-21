import {
    RawAesKeyringNode,
    buildClient,
    CommitmentPolicy,
    RawAesWrappingSuiteIdentifier,
  } from '@aws-crypto/client-node'
  import { randomBytes } from 'crypto'

const { encrypt, decrypt } = buildClient(
    CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
);

function createKeyring() {
  /* The wrapping suite defines the AES-GCM algorithm suite to use. */
  const wrappingSuite = RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING;

  // Get your plaintext Wrapping key from wherever you store it.
  const unencryptedWrappingkey = randomBytes(32);

  const wrappingKeyName = 'aes-name';
  const wrappingKeyNamespace = 'aes-namespace';

  const input = {
    keyName: wrappingKeyName,
    keyNamespace: wrappingKeyNamespace,
    unencryptedMasterKey: unencryptedWrappingkey,
    wrappingSuite: wrappingSuite
  };

  /* Configure the Raw AES keyring. */
  const keyring = new RawAesKeyringNode(input);

  return keyring;
}

async function AESEncrypt(keyring: RawAesKeyringNode) {
  console.log('calling');
    
  /* Find data to encrypt. */
  const plainTextInput = 'OSDAnywhereMultiDataSource2022';
  
  console.log("plainText: ", plainTextInput);

  /* Encode the data (Optional) */
  const encoded = Buffer.from(plainTextInput)

  /* Encrypt the data. */
  const { result, messageHeader }  = await encrypt(keyring, encoded);

  return { result, messageHeader };
}

async function demoGreenCase() {
    console.log("========demoGreenCase========")
    const keyring = createKeyring();
    const { result, messageHeader } = await AESEncrypt(keyring);
    console.log("encryptedDataKey: ", messageHeader.encryptedDataKeys[0].encryptedDataKey);

    const decrypted = await decrypt(keyring, result);
    // Data Key will not change
    console.log("decryptedDataKey: ", decrypted.messageHeader.encryptedDataKeys[0].encryptedDataKey);
    console.log("plaintextOutput: ", decrypted.plaintext.toString());  
}

async function demoRedCase() {
    console.log("========demoRedCase========")
    const keyring1 = createKeyring();
    const { result, messageHeader } = await AESEncrypt(keyring1);
    console.log("encryptedDataKey: ", messageHeader.encryptedDataKeys[0].encryptedDataKey);

    const keyring2 = createKeyring();
    // Expect Error: unencryptedDataKey has not been set
    const { plaintext } = await decrypt(keyring2, result);
    console.log("plaintextOutput: ", plaintext.toString());  
}

demoGreenCase().then(() => demoRedCase());
