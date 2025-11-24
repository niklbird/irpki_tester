/// This file remains a TODO: Alligning the field names with the RFC ASN.1 definitions


// CMS SignedData labels

const signedData: &'static str = "signedData";
const version: &'static str = "version";
const digestAlgorithms: &'static str = "digestAlgorithms";
const encapContentInfo: &'static str = "encapContentInfo";
const certificates: &'static str = "certificates";
const signerInfos: &'static str = "signerInfos";


const digestAlgorithmIdentifier: &'static str = "digestAlgorithmIdentifier";

const eContentType: &'static str = "eContentType";
const eContent: &'static str = "eContent";

const signerIdentifier: &'static str = "signerIdentifier";
const digestAlgorithm: &'static str = "digestAlgorithm";
const signedAttributes: &'static str = "signedAttributes";
const unsignedAttributes: &'static str = "unsignedAttributes";
const attribute: &'static str = "attribute";
const attrType: &'static str = "attrType";
const attrValues: &'static str = "attrValues";
const attrValue: &'static str = "attrValue";
const signatureAlgorithm: &'static str = "signatureAlgorithm";
const signatureValue: &'static str = "signature";

// X509
const tbsCertificate: &'static str = "tbsCertificate";
const tbsSerialNumber: &'static str = "tbsSerialNumber";
const x509signatureAlgorithm: &'static str = "x509signatureAlgorithm";
const x509signatureValue: &'static str = "x509signature";

const tbsSignatureAlgorithm: &'static str = "x509signatureAlgorithm";
const issuer: &'static str = "issuer";
const subject: &'static str = "subject";

const name: &'static str = "name";
const names: &'static str = "names";
const nametype: &'static str = "nameType";
const namevalue: &'static str = "nameValue";
const rdnSequence: &'static str = "rdnSequence";

const validity: &'static str = "validity";
const notBefore: &'static str = "notBefore";
const notAfter: &'static str = "notAfter";

const subjectPublicKeyInfo: &'static str = "subjectPublicKeyInfo";
const subjectPublicKeyAlgorithm: &'static str = "subjectPublicKeyAlgorithm";
const subjectPublicKey: &'static str = "subjectPublicKey";

const extensions: &'static str = "extensions";
const extension: &'static str = "extension";
const extnID: &'static str = "extnID";
const critical: &'static str = "critical";
const extnValue: &'static str = "extnValue";

const authorityKeyIdentifierExtension: &'static str = "authorityKeyIdentifier";
const subjectKeyIdentifierExtension: &'static str = "subjectKeyIdentifier";
const keyUsageExtension: &'static str = "keyUsage";
const extendedKeyUsageExtension: &'static str = "extendedKeyUsage";
const basicConstraintsExtension: &'static str = "basicConstraints";
const cRLDistributionPointsExtension: &'static str = "cRLDistributionPoints";
const authorityInfoAccessExtension: &'static str = "authorityInfoAccess";
const keyIdentifier: &'static str = "keyIdentifier";
const asidExtension: &'static str = "asIDExtension";
const ipAddrExtensions: &'static str = "ipAddrBlocksExtension";



const RouteOriginAuthorization: &'static str = "routeOriginAuthorization";
const asID: &'static str = "asID";
const ipAddrBlocks: &'static str = "ipAddrBlocks";
const ROAIPAddressFamily: &'static str = "roaIPAddressFamily";
const addressFamily: &'static str = "addressFamily";
const addresses: &'static str = "addresses";
const afi: &'static str = "afi";
const ROAAddresses: &'static str = "roaAddresses";
const ROAAddress: &'static str = "roaAddress";
const maxLength: &'static str = "maxLength";
const address: &'static str = "address";


const Manifest: &'static str = "manifest";
const manifestNumber: &'static str = "manifestNumber";
const thisUpdate: &'static str = "thisUpdate";
const nextUpdate: &'static str = "nextUpdate";
const fileList: &'static str = "fileList";
const fileHashAlg: &'static str = "fileHashAlg";
const file: &'static str = "file";
const hash: &'static str = "hash";
const fileAndHash: &'static str = "fileAndHash";

