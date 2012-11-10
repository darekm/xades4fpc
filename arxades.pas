{$IFDEF XHTML}
 {%main htarxades}
{$ELSE}
{.$I start.inc}

unit arxades;

interface
uses
  sysutils,
  {$IFDEF MEM_CHECK}MemCheck,{$ENDIF}
  Classes, DOM, XMLRead, XMLWrite,XMLWritec14,
//  wCrypt2,
  EncdDecd,
  kom2,
  wpstring,
//  jwawincrypt,
  arcert,
  synacode,
//  dialogs,
  xmlc14n;
//  windows;
{$ENDIF}
{$H+}
const
    AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
    AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
    RSA_1_5    = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
    RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    URI_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    URI_DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
    URI_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    URI_C14N  = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    URI_C14N_COM  = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    URI_XMLDSIG   = 'http://www.w3.org/2000/09/xmldsig#';
    URI_XADES     = 'http://uri.etsi.org/01903/v1.3.2#';


  type
     xmlstring = ansistring;
     stringb64 = ansistring;

     xadesMethod =(C14N,c14NWith); //xmllint



       tXades = class;
       tXadesObject = class(tComponent)
         private
          fobject : tXmlDocument;
          fXades  : tXades;
          fURI    : ansistring;
          fTypeReference : ansistring;
          property xmlObject : tXmlDocument read fObject;
         public
          objectNode : tDomElement;
         constructor create(aOwner : tXades;const aURI : string);
         destructor destroy;override;
         procedure load(const fName : ansistring);
         procedure loadStr(const fStr : ansistring);
         function dsObject: tDomElement;virtual;
       end;
       tXadesProperties = class(tXadesObject)
        public
         fTarget : ansistring;
         constructor create(aOwner : tXades;const aURI : string);
         function dsObject: tDomElement;override;
         function xadesCert:tDomElement;
       end;

       tXades  = class(tComponent)
       protected
           fdoc: TXMLDocument;
           curr :TDOMElement;
           sId  : ansistring;
           fDocument : tXadesObject;
           fSigned   : tXadesProperties;
           fCertificate :TCertificate;
//           function referenceSigned:tDomElement;
//           function referenceDocument:tDomElement;
//           function GetSignatureValue(ACertificate: TCertificate; const AXml: string): string;
          public
            constructor create;
//            procedure setCanonicalMethod(aMethod :xadesMethod);
            destructor destroy;override;
            procedure save(const fName : string);
            function saveStr : ansiString;
//            procedure saveCan(const fName : string);
            function signedInfo:tDomElement;
            function signatureValue(aSignedInfo: tDomNode):tDomElement;
            function dsreference(aObject: tXadesObject):tDomElement;
            function keyInfo:tDomElement;
            procedure sign;
//            function  GetDigestValue(const AXml: xmlstring): string;
//            function  GetAvailableProviderType: cardinal;
            function GetCertificate: TCertificate;
            function digestValue(aNode : tDomElement):xmlstring;
            function digestValueB64(aNode : tDomElement) : stringb64;

            property doc : tXMLDocument read fdoc;
            property signed : tXadesProperties read fSigned;
            property document : tXadesObject read fDocument;
            property certificate : tCertificate read fCertificate write fCertificate;
            end;


type
  EXadesMessageError = class(Exception);


function testCer: ansiString;
function testCan:ansiString;
function testProp:ansiString;
function testCC:ansiString;

implementation

function testCC;
var
  i  : integer;
  s6,
  sw,

  sn : ansiString;
begin
sn:='<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Dokument-0" MimeType="text/xml">'#10;
sn:=sn+'    <test>abcdefghjj</test>'#10;
sn:=sn+'  </ds:Object>';
s6:='qCaaxtiN9/iTfobjx2bmSBAm32s=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';


sn:='<xades:SignedProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="PEMI-SignedProperties-1">'#10;
sn:=sn+'        <xades:SignedSignatureProperties>'#10;
sn:=sn+'          <xades:SigningTime>2009-08-12T16:32:27Z</xades:SigningTime>'#10;
sn:=sn+'          <xades:SigningCertificate>'#10;
sn:=sn+'            <xades:Cert>'#10;
sn:=sn+'              <xades:CertDigest>'#10;
sn:=sn+'                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>'#10;
sn:=sn+'                <ds:DigestValue>CfiJnO+siIYUixa136UI4WvjJSI=</ds:DigestValue>'#10;
sn:=sn+'              </xades:CertDigest>'#10;
sn:=sn+'              <xades:IssuerSerial>'#10;
sn:=sn+'                <ds:X509IssuerName>SERIALNUMBER=Nr wpisu: 1, CN=CERTUM QCA, O=Unizeto Technologies S.A., C=PL</ds:X509IssuerName>'#10;
sn:=sn+'                <ds:X509SerialNumber>25674</ds:X509SerialNumber>'#10;
sn:=sn+'              </xades:IssuerSerial>'#10;
sn:=sn+'            </xades:Cert>'#10;
sn:=sn+'          </xades:SigningCertificate>'#10;
sn:=sn+'        </xades:SignedSignatureProperties>'#10;
sn:=sn+'      </xades:SignedProperties>';
s6:='yMAa8AD2jLwL/WtcMBHM+ezq0Ok=';

sw:=czytajString('xades_Signedproperties');
for i:= 1 to length(sn)do
  if sn[i]<>sw[i] then
    result:=' ';

  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';

end;

function testProp:ansiString;
var
  tm : tMemoryStream;
  s6,
  sd,
  sn : ansiString;
  i  : integer;
begin

sn:='';

sn:=sn+'<SignedProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="SignP">';
sn:=sn+'<SigningTime>2008-08-25T01:43:00+03:00</SigningTime>';
sn:=sn+'<SigningCertificate><Cert><CertDigest><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>ZZRzWFnvjm8elSKnyWcupdTuLBw=</DigestValue>';
sn:=sn+'</CertDigest><IssuerSerial>';
sn:=sn+'<ds:X509IssuerName>CN=TÜBİTAK UEKAE Kamu Elektronik Sertifika Hizmet Sağlayıcısı-Test,OU=Kamu Sertifikasyon Merkezi-Test,OU=Ulusal Elektronik ve Kriptoloji Araştırma';
sn:=sn+' Enstitüsü-UEKAE-Test,O=Türkiye Bilimsel ve Teknolojik Araştırma Kurumu-TÜBİTAK-Test,L=Gebze-Kocaeli,C=TR</ds:X509IssuerName>';
sn:=sn+'<ds:X509SerialNumber>41</ds:X509SerialNumber></IssuerSerial></Cert></SigningCertificate><SignaturePolicyIdentifier><SignaturePolicyImplied></SignaturePolicyImplied></SignaturePolicyIdentifier></SignedProperties>';
//<UnsignedProperties><SignatureTimeStamp><HashDataInfo uri=""/><EncapsulatedTimeStamp Id="SignatureTimeStamp">MIIONDAVAgEAMBAMDk9wZXJhdGlvbiBPa2F5MIIOGQYJKoZIhvcNAQcCoIIOCjCCDgYCAQMxCzAJ&#13;

s6:='9kHcG+Pzas1z/aztBFfP2dr9ASE=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';

sn:='';
sn:=sn+'<SignatureProperties xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:foo="http://example.org/foo" Id="signature-properties-1">'#10;
sn:=sn+'          <SignatureProperty Target="#signature">'#10;
sn:=sn+'            <SignerAddress xmlns="urn:demo"><IP>192.168.21.138</IP></SignerAddress>'#10;
sn:=sn+'          </SignatureProperty>'#10;
sn:=sn+'        </SignatureProperties>';
s6:='ETlEI3y7hvvAtMe9wQSz7LhbHEE=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';


sn:='';
//sn:='<ds:Object Id="PEMI-Object-1" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">'
//sn:=sn+'<xades:QualifyingProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#PEMI-Signature-Id-1">';
sn:=sn+'<xades:SignedProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="PEMI-SignedProperties-1">';
sn:=sn+'<xades:SignedSignatureProperties>';
sn:=sn+'<xades:SigningTime>2009-08-30T16:16:34Z</xades:SigningTime>';
sn:=sn+'<xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>CfiJnO+siIYUixa136UI4WvjJSI=</ds:DigestValue></xades:CertDigest>';
sn:=sn+'<xades:IssuerSerial><ds:X509IssuerName>SERIALNUMBER=Nr wpisu: 1,CN=CERTUM QCA,O=Unizeto Technologies S.A.,C=PL</ds:X509IssuerName><ds:X509SerialNumber>25674</ds:X509SerialNumber></xades:IssuerSerial>';
sn:=sn+'</xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties>'#10;
sn:=sn+'</xades:SignedProperties>';

//sn:=sn+'</xades:QualifyingProperties>';
//sn:=sn+'</ds:Object>';

s6:='2vsJyCyoo0yW/WcC4qJnBwfO+2U=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';

//sn:='<ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="QualifyingProperties_afe0bc42-aede-497a-ac5e-bb5a17e331c8_45" Target="#Signature_afe0bc42-aede-497a-ac5e-bb5a17e331c8_1f">';
sd:='';
//sn:='<xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="QualifyingProperties_afe0bc42-aede-497a-ac5e-bb5a17e331c8_45" Target="#Signature_afe0bc42-aede-497a-ac5e-bb5a17e331c8_1f">';
sd:=sd+'<xades:SignedProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"';
sd:=sd+' Id="SignedProperties_afe0bc42-aede-497a-ac5e-bb5a17e331c8_48">';
sd:=sd+'<xades:SignedSignatureProperties Id="SignedSignatureProperties_afe0bc42-aede-497a-ac5e-bb5a17e331c8_0c">';
sd:=sd+'<xades:SigningTime>2009-08-30T19:47:49+02:00</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>';
sd:=sd+'<ds:DigestValue>CfiJnO+siIYUixa136UI4WvjJSI=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>serialNumber=Nr wpisu: 1,CN=CERTUM QCA,O=Unizeto Technologies S.A.,C=PL</ds:X509IssuerName>';
sd:=sd+'<ds:X509SerialNumber>25674</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties>';
sd:=sd+'<xades:SignedDataObjectProperties Id="SignedDataObjectProperties_afe0bc42-aede-497a-ac5e-bb5a17e331c8_4d"><xades:DataObjectFormat ObjectReference="#Reference1_afe0bc42-aede-497a-ac5e-bb5a17e331c8_21"><xades:Description>MIME-Version: 1.0&#xD;'#10;
sd:=sd+'Content-Type: text/xml&#xD;'#10;
sd:=sd+'Content-Transfer-Encoding: binary&#xD;'#10;
sd:=sd+'Content-Disposition: filename="XMLFile4.xml"</xades:Description><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties>';
sd:=sd+'</xades:SignedProperties>';
   s6:='NnzQygX2EpG/R6GNpwcf/0UseaU=';
  result:=encodeString(sha1(sd));
  if result<>s6 then
    result:='ss';

sn:='';
sn:=sn+'<xades:SignedProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="SignedProperties_afe0bc42-aede-497a-ac5e-bb5a17e331c8_48">';
sn:=sn+'<xades:SignedSignatureProperties Id="SignedSignatureProperties_afe0bc42-aede-497a-ac5e-bb5a17e331c8_0c">';
sn:=sn+'<xades:SigningTime>2009-08-30T19:47:49+02:00</xades:SigningTime>';
sn:=sn+'<xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>CfiJnO+siIYUixa136UI4WvjJSI=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial>';
sn:=sn+'<ds:X509IssuerName>serialNumber=Nr wpisu: 1,CN=CERTUM QCA,O=Unizeto Technologies S.A.,C=PL</ds:X509IssuerName><ds:X509SerialNumber>25674</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties>';
sn:=sn+'<xades:SignedDataObjectProperties Id="SignedDataObjectProperties_afe0bc42-aede-497a-ac5e-bb5a17e331c8_4d"><xades:DataObjectFormat ObjectReference="#Reference1_afe0bc42-aede-497a-ac5e-bb5a17e331c8_21">';
sn:=sn+'<xades:Description>MIME-Version: 1.0&#xD;'#10;
sn:=sn+'Content-Type: text/xml&#xD;'#10;
sn:=sn+'Content-Transfer-Encoding: binary&#xD;'#10;
sn:=sn+'Content-Disposition: filename="XMLFile4.xml"</xades:Description><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat>';
sn:=sn+'</xades:SignedDataObjectProperties></xades:SignedProperties>';
for i:= 1 to length(sn)do
  if sn[i]<>sd[i] then
    result:=' ';
//  sn:=sn+'<xades:UnsignedProperties Id="UnsignedProperties_afe0bc42-aede-497a-ac5e-bb5a17e331c8_53"/></xades:QualifyingProperties>';
//sn:=sn+'</ds:Object>'

   s6:='NnzQygX2EpG/R6GNpwcf/0UseaU=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';

end;


function testCan:ansiString;
var
//  tm : tMemoryStream;
  s6,
//  sd,
  sn : ansiString;
begin
  sn:='';
  sn:='<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Dokument-0" MimeType="text/xml">'
      +'<test>'#10
      +'<t>a</t>'#10
      +'</test>'
      +'</ds:Object>';
  s6:='kEaE9Pupi3N/yk/Lkh7G5z4h2Vg=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';
  sn:='<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Dokument-0" MimeType="text/xml"><test>'#10
   +'<b><t>a</t></b>'#10
   +'</test></ds:Object>';
   s6:='S/LzzR1DODJNnOHCy9nZoHNqJMg=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';

  sn:='<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Dokument-0" MimeType="text/xml"><test>'#10
   +'<b>'#10
   +'<t>a</t></b>'#10
   +'</test></ds:Object>';
   s6:='U6bqz7lLFF2lf8Qkm/E9HDMTATk=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';

  sn:='<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Dokument-0" MimeType="text/xml"><test>'#10
   +'<b>'#10
   +'   <t>a</t></b>'#10
   +'</test></ds:Object>';
   s6:='brSdUzYG4khdtsPSgirwKseVTTg=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';


  sn:='<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Object1_0c3128b2-97d4-4d6f-b9b1-9c485142c051" MimeType="text/xml"><test>'#10
   +'<b>'#10
   +'   <t>a</t></b>'#10
   +'</test></ds:Object>';
   s6:='wIFUEqSutAl13kbIkPwjKSFABbk=';
  result:=encodeString(sha1(sn));
  if result<>s6 then
    result:='ss';

end;


function ReversedString(const AStr: string): string;
var
  I: Integer;
  P: PChar;
begin
  SetLength(Result, Length(AStr));
  P := PChar(Result);
  for I := Length(AStr) downto 1 do
  begin
    P^ := AStr[I];
    Inc(P);
  end;
end;



function testCer: ansiString;
var
  tm : tMemoryStream;
  s6,
  sd,
  sn : ansiString;
begin
sn:='';
//sn:='<ds:X509Data xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Certificate>';
//sn:='<ds:X509Certificate xmlns:ds="http://www.w3.org/2000/09/xmldsig#">';
//sn:='<ds:X509Certificate xmlns:ds="http://www.w3.org/2000/09/xmldsig#">';
sn:=sn+'MIIE6TCCA9GgAwIBAgICZEowDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCUEwx'
+'IjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xEzARBgNVBAMTCkNF'
+'UlRVTSBRQ0ExFDASBgNVBAUTC05yIHdwaXN1OiAxMB4XDTA4MDUyMDE4MDMxNFoX'
+'DTEwMDUyMDE4MDMxNFowgc4xDjAMBgNVBAMMBU1BREFSMQ4wDAYDVQQqDAVCRUFU'
+'QTEUMBIGA1UEBAwLU1VDSEFST1dTS0ExGjAYBgNVBAUTEVBFU0VMOjc5MDYwNjEy'
+'MTYwMRkwFwYDVQQKDBBNQURBUiBTUC4gWiBPLk8uMS0wKwYDVQQQMCQME1NLxYFP'
+'RE9XU0tJRUogMTJELzMMDTQxLTgxOSBaQUJSWkUxDzANBgNVBAcMBlpBQlJaRTES'
+'MBAGA1UECAwJxZpMxIRTS0lFMQswCQYDVQQGEwJQTDCBnzANBgkqhkiG9w0BAQEF';

sn:=sn+'AAOBjQAwgYkCgYEApW8rqS/u8ySAJDOTEEAfeOrCNeTGBCvu/QXDYu2QwPbAaOs7'
+'Xrf4YyNpJ9dYsyxcPo0IDi7+3QwLjVVHPW73MN96iK9AZstNTvrk1fxze/kJCzcz'
+'b6WCozRt3jMqAGlDmlRqM/U1BXGGw4u/J9CI39wBGUkc7tu/Mj1DvvAgQPkCAwEA'
+'AaOCAcQwggHAMA4GA1UdDwEB/wQEAwIGQDCB9QYDVR0gAQH/BIHqMIHnMIHkBgsq'
+'hGgBhvZ3AgQBATCB1DAtBggrBgEFBQcCARYhaHR0cDovL3d3dy5jZXJ0dW0ucGwv'
+'cmVwb3p5dG9yaXVtMIGiBggrBgEFBQcCAjCBlQyBkkNlcnR1bSBRQ0EgUHJvZmVz'
+'am9uYWxueSAtIGt3YWxpZmlrb3dhbnkgY2VydHlmaWthdCB3eWRhbnkgcHJ6ZXog'
+'VW5pemV0byBUZWNobm9sb2dpZXMgUy5BLiB6Z29kbmllIHogd3ltYWdhbmlhbWkg'
+'VXN0YXd5IG8gcG9kcGlzaWUgZWxla3Ryb25pY3pueW0uMDkGCCsGAQUFBwEDAQH/'
+'BCowKDAOBgkqhGgBZQMBAQIKAQIwFgYGBACORgECMAwTA1BMTgICJxACAQAwDAYD'
+'VR0TAQH/BAIwADAdBgNVHQ4EFgQUa8atyF1wFb7a7JgRkZ+sNQcVuWQwLQYDVR0f'
+'BCYwJDAioCCgHoYcaHR0cDovL2NybC5jZXJ0dW0ucGwvcWNhLmNybDAfBgNVHSME'
+'GDAWgBQdFuo9XqpGT6ic0s3jSLe7XkwCbzANBgkqhkiG9w0BAQUFAAOCAQEAZKc6'
+'sXEJVRscgP8Xq+ZxbXvIvU7+G/0TvySjXKJHJBncHye9Qd2jks/5I8oDvmTNKLOD'
+'M1rN4hoLWk70APuLZRVW5vvbMA3Q5BB0erOjBAS1Fl7G/DmVtt9UjDo17ro8vR8g'
+'0CqTnMA0xLLXRGvoCmh9Pc4E9aAyAzcHdO6ALYqkbAgWeLk4VPHfqqRiiLTD4XUs'
+'qrSmkKmxwcpXWLHdLSJhHvpNDYYsfTOiWGC99OxWVjAYytVY6KEahUUIepLTQjSl'
+'J0YA5QGQkRVhcg6pVefqNp7CsBmAEp7GalmdTCKboARmt+arWwPcbLMkeLHQCtBp'
+'tnUPfKJuxTZW+5kLWQ==';
//sn:=sn+'</ds:X509Certificate>';

//sn:=sn+'</ds:X509Certificate></ds:X509Data>';

//sn:='<xades:IssuerSerial><ds:X509IssuerName>serialNumber=Nr wpisu: 1,CN=CERTUM QCA,O=Unizeto Technologies S.A.,C=PL</ds:X509IssuerName><ds:X509SerialNumber>25674</ds:X509SerialNumber></xades:IssuerSerial>';


result:=encodeString(sha1(decodestring(sn)));
s6:='CfiJnO+siIYUixa136UI4WvjJSI=';
if s6<>result then
  result:=result+' ';

end;

function canonicalize(aobject : tDomNode):String;
var
  tm : tMemoryStream;
//  s6,
//  sn : ansiString;
//  tcc : TXCanonicalizer;

begin

   tm:=tMemoryStream.create;
   writeXMLc14(aObject,tm);
   SetLength(result,tm.size);
   Move(tm.memory^,result[1],tm.size);
   tm.Free;
//   delete(result,length(result),1);
   zapiszString(result,justPlik(tDomElement(aObject).TagName));

{

   tcc:=TXCanonicalizer.create;
   result:=tcc.canonicalize(aObject);
   tcc.free;

}


   {
   result:='<Object Id="object">c29tZSB0ZXh0</Object>';
   result:='c29tZSB0ZXh0';
   s6:=decodeString(result);
   sn:=sha1(s6);
   if s6<>sn then
     result:=result;
   if (sn<>'N6pjx3OY2VRHMmLhoAV8HmMu2nc=')  then
     result:=result+' ';
   }
//   sn:=encodeString(sn);
{
   result:='<Object xmlns="http://www.w3.org/2000/09/xmldsig#" Id="object">some text</Object>';
//   result:='some text';
   s6:=sha1(result);

   sn:=decodeString('7/XTsHaBSOnJ/jXD5v0zL6VKYsk=');
   if sn<>s6 then
   result:=result+' ';
 }

{   sn:='<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Dokument-0" MimeType="text/xml"><test>abcdefghjj</test></ds:Object>';
   if result <>sn then begin
     sn:=sn+' ';
   end;
}
//   sn:='<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Dokument-0" MimeType="text/xml"><test>abcdefghjj</test></ds:Object>';

//   result:='<test>abcdefghjj</test>';

{   s6:='z024jIJQjcyZWl7mPMG55SZn8I0=';
   s6:=decodeString(s6);
   sn:=sha1(sn);
}
//   if sn=s6 then
//     result:=result+' ';

//   result:='<ds:Object Id="Object1_da94a331-5213-463b-b096-c71950018d1d" MimeType="text/xml"><test>abcdefghjj</test></ds:Object>';
end;

function HexToOS(const HexStr: string): ansiString;
const
  Digits = '0123456789ABCDEF';
var
  I, J, K, P: Integer;
  B: Byte;
  U: string;
begin
  SetLength(Result,Length(HexStr) shr 1);
  J := 1;
  B := 0;
  K := 0;
  U := UpperCase(HexStr);
  for I := 1 to Length(U) do begin
    P := Pos(U[I],Digits);
    if P > 0 then begin
      B := (B shl 4) + P - 1;
      Inc(K);
    end;
    if K = 2 then begin
      Result[J] := Char(B);
      Inc(J);
      B := 0;
      K := 0;
    end;
  end;
  SetLength(Result,J-1);
end;


constructor tXadesObject.create;
begin
  fXades:=aOwner;
  fUri:=aUri;
  fObject:=TXMLDocument.Create;
  inherited create(fXades);
end;
destructor tXadesObject.destroy;
begin
  inherited destroy;
  freeAndNil(fObject);
end;
function tXades.digestValue;
var
  sn,
  s      : string;
begin

  s := 'abc';
  sn:=sha1(s);
{  with TSHA1.Create(Pointer(Msg)^,Length(Msg)) do begin
    Done(nil);
    D := Digest;
    Free;
  end;}
  if sn = HexToOS('a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d') then  begin
//    writeln(sn);
  end;
  {
   s:='<ds:Object Id="Object1_ee8d4597-84b4-41df-ae32-c40141dc72fd" MimeType="text/xml"><Deklaracja';
   s:=s+' xmlns="http://crd.gov.pl/wzor/2011/12/12/725/"';
   s:=s+' xmlns:etd="http://crd.gov.pl/xml/schematy/dziedzinowe/mf/2011/06/21/eD/DefinicjeTypy/"';
   s:=s+' xsi:schemaLocation="http://crd.gov.pl/wzor/2011/12/12/725/ http://crd.gov.pl/wzor/2011/12/12/725/schemat.xsd"';
   s:=s+' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';
   s:=s+'></Deklaracja></ds:Object>';
   sn:=encodeString(sha1(s));
   if sn<>'Im1ckLO/eHJ6QaHf8uhpJ8FbAa8=' then
     result:=result+' ';
}

s:='<ds:Object Id="Object1_9a793856-c959-4e5d-9160-621fca35416d" MimeType="text/xml"><Deklaracja';
s:=s+' xmlns:etd="http://crd.gov.pl/xml/schematy/dziedzinowe/mf/2011/06/21/eD/DefinicjeTypy/"';
s:=s+' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';
s:=s+' xsi:schemaLocation="http://crd.gov.pl/wzor/2011/12/12/725/ http://crd.gov.pl/wzor/2011/12/12/725/schemat.xsd"';
s:=s+'></Deklaracja></ds:Object>';
//   sn:=canonicalize(s);
   sn:=encodeString(sha1(s));
   if sn<>'MHMddbkfpDzj2fDXeaui27frQ/k=' then
     result:=result+' ';

   s:=canonicalize(ANode);
   sn:=sha1(s);

   result:=Certificate.getDigestValue(s);
   if sn<>result then
     result:=result+'';
//   result:=sha1(s);


end;

function tXades.digestValueb64;
begin
  result:=encodeString(digestValue(aNode));
end;
procedure tXadesObject.load;
begin
//   fObject:=fXades.doc.createElement('ds:Object');
   readXMLFile(fObject,fName);
end;

procedure tXadesObject.loadStr;
var
  tm : tMemoryStream;
begin
   freeandnil(fObject);
   tm:=tMemoryStream.create;
   tm.write(Pointer(fstr)^,length(fstr));
   tm.seek(0,0);
   readXMLfile(fObject,tm);
   tm.Free;

end;



function tXadesObject.dsObject;
begin
  result:=fXades.doc.createElement('ds:Object');
  result.setAttribute('xmlns:ds',URI_XMLDSIG);
  result.setAttribute('Id',fUri);
  result.setAttribute('MimeType','text/xml');
  result.appendChild(XMLObject.DocumentElement.cloneNode(true,fXades.doc));
  ObjectNode:=result;
end;

constructor tXadesProperties.create;
begin
  inherited create(aOwner,aUri);
  fTypeReference:='http://uri.etsi.org/01903#SignedProperties';
end;

function tXadesProperties.dsObject;
var
  xData,
  xElement,
  xQualify,
  xSigned : tDomElement;

begin
   xData:=fXades.doc.createElement('xades:SignedSignatureProperties');
  xElement:=fXades.doc.createElement('xades:SigningTime');
   xElement.appendChild(fXades.doc.createtextNode('2009-08-12T16:32:27Z'));
   xData.appendChild(xElement);

   xElement:=fXades.doc.createElement('xades:SigningCertificate');
   xElement.appendChild(xadesCert);
   xData.AppendChild(xElement);

   xSigned:=fXades.doc.createElement('xades:SignedProperties');
   xSigned.setAttribute('xmlns:ds',URI_XMLDSIG);
   xSigned.SetAttribute('xmlns:xades',URI_XADES);
   xSigned.setAttribute('Id',fUri);
   ObjectNode:=xSigned;
   xSigned.AppendChild(xData);
   xQualify:=fXades.doc.createElement('xades:QualifyingProperties');
   xQualify.SetAttribute('xmlns:xades',URI_XADES);
   xQualify.setAttribute('Target','#'+fTarget);
   xQualify.appendChild(xSigned);


   result:=fXades.doc.createElement('ds:Object');
   result.appendChild(xQualify);

end;

function tXadesProperties.xadesCert;
var
  xData,
  xElement : tDomElement;
//  xNode    : tDomElement;
begin
  result:=fXades.doc.createElement('xades:CertDigest');
  xElement:=fXades.doc.createElement('ds:DigestMethod');
  xElement.setAttribute('Algorithm',URI_SHA1);
  result.appendChild(xElement);

  xElement:=fXades.doc.createElement('ds:DigestValue');

  xElement.appendChild(fXades.doc.createtextNode(fXades.certificate.x509Digest));
  result.appendChild(xElement);
  xElement:=result;
  result:=fXades.doc.createElement('xades:Cert');
  result.appendChild(xElement);
  xData:=fXades.doc.createElement('xades:IssuerSerial');
  xElement:=fXades.doc.createElement('ds:X509IssuerName');
  xElement.appendChild(fXades.doc.createtextNode(fXades.certificate.IssuerName));
//****  xElement.appendChild(fXades.doc.createtextNode('SERIALNUMBER=Nr wpisu: 1,CN=CERTUM QCA,O=Unizeto Technologies S.A.,C=PL'));
  xData.appendChild(xElement);
{  xElement:=fXades.doc.createElement('ds:IssuerAll');
  xElement.appendChild(fXades.doc.createtextNode(fXades.certificate.allname));
  xData.appendChild(xElement);}
  xElement:=fXades.doc.createElement('ds:X509SerialNumber');
  xElement.appendChild(fXades.doc.createtextNode(fXades.certificate.serialnumberDec));
  xData.appendChild(xElement);

  result.appendChild(xData);



end;

constructor TXades.Create;
var
  cfg: TDOMElement;

begin
  fdoc := TXMLDocument.Create;
  sId:='-1';
  inherited Create(nil);

    cfg := doc.CreateElement('ds:Signature');
    cfg.setAttribute('xmlns:ds','http://www.w3.org/2000/09/xmldsig#');
    cfg.setAttribute('Id','PEMI-Signature'+sId);

//    cfg.setAttribute('ds:noNamespaceSchemaLocation','http://uri.etsi.org/01903/v1.3.2/XAdES.xsd');

    doc.AppendChild(cfg);
    curr:=cfg;
  fDocument:=tXadesObject.create(self,'Dokument-0');
  fSigned:=tXadesProperties.create(self,'PEMI-SignedProperties'+sId);
  fSigned.fTarget:='PEMI-Signature'+sId;


end;


destructor TXades.Destroy;
begin
//  freeandnil(fSigned);
  inherited Destroy;
  freeandnil(fdoc);
  freeandnil(fCertificate);
end;

procedure tXades.save;
begin
    WriteXMLFile(doc, Fname);
end;

function tXades.saveStr;
var
  tm : tMemoryStream;
begin
   tm:=tMemoryStream.create;
   writeXML(doc,tm);
   SetLength(result,tm.size);
   Move(tm.memory^,result[1],tm.size);
   tm.Free;
end;

{
procedure tXades.saveCan;
var
 sn : string;
begin
  sn:=canonicalize(tDomElement(doc));
  zapiszString(sn,fname);
end;
}

procedure tXades.sign;
var
  xCurrent : tDomNode;
begin
  curr.AppendChild(document.dsobject);
  curr.AppendChild(signed.dsObject);
  xCurrent:=curr.insertBefore(keyInfo,document.objectNode);
  curr.InsertBefore(signatureValue(curr.insertBefore(signedInfo,xCurrent)),xCurrent);
end;

function tXades.dsreference;
var
  xMethod : tDomElement;
begin
  result:=doc.createElement('ds:Reference');
  result.setAttribute('URI','#'+aObject.fUri);
  if aObject.fTypeReference<>'' then
     result.setAttribute('Type',aObject.fTypeReference);

  xMethod:=doc.createElement('ds:DigestMethod');
  xMethod.setAttribute('Algorithm',URI_SHA1);
  result.appendChild(xMethod);
  xMethod:=doc.createElement('ds:DigestValue');
//  if aObject.fTypeReference='' then
    xMethod.appendChild(doc.createtextNode(digestValueB64(aObject.objectNode)));
{  else
  xMethod.appendChild(doc.createtextNode('5jPwwhXwYAsOPAOS4HsN5XjW8Mg='));
}  result.appendChild(xMethod);

end;


function tXades.signedInfo;
var
  xMethod : tDomElement;
begin
  result:=doc.createElement('ds:SignedInfo');
{  result.setAttribute('xmlns:ds',URI_XMLDSIG);
  result.setAttribute('Id','SignedInfo'+sId);
}  curr.AppendChild(result);
  xMethod:=doc.createElement('ds:CanonicalizationMethod');
  xMethod.setAttribute('Algorithm',URI_C14N);
  result.appendChild(xMethod);
  xMethod:=doc.createElement('ds:SignatureMethod');
  xMethod.setAttribute('Algorithm',URI_RSA_SHA1);
  result.appendChild(xMethod);
  result.appendChild(dsreference(Document));
  result.appendChild(dsreference(Signed));

end;

function tXades.signatureValue;
var
  cSignature  : TDOMElement;
  sigValue  : ansistring;
  canValue  : ansiString;
begin
  csignature:=doc.createElement('ds:SignatureValue');
  cSignature.setAttribute('Id','SignatureValue'+sId);
  canValue:=Canonicalize(ASignedInfo);

//  MessageDlg(canValue, mtError, [mbOK], 0);
 {
  xElement:=doc.createElement('ds:IssuerAll');
  xElement.appendChild(doc.createtextNode(canValue));
  cSignature.appendChild(xElement);
  }

  sigValue :=   encodeBase64(fCertificate.GetSignatureValue( canValue));

  cSignature.appendChild(doc.createtextNode(sigValue));
  result:=cSignature;
end;

function tXades.keyInfo;
var
  xData,
  xCertificate : tDomElement;
begin
   result:=doc.createElement('ds:KeyInfo');
   result.setAttribute('Id','KeyInfo'+sid);
   xData:=doc.createElement('ds:X509Data');
   xCertificate:=doc.createElement('ds:X509Certificate');
   xCertificate.appendChild(doc.createtextNode(certificate.x509Data));
   xData.appendChild(xCertificate);
   result.appendChild(xData);


end;





(*
function tXades.GetDigestValue(const AXml: xmlstring): string;
var
  context: HCRYPTPROV;
  hash: HCRYPTHASH;
  data: TmemoryStream;
  hashSize, dwordSize: cardinal;
begin
  if not CryptAcquireContext(context, nil, nil, GetAvailableProviderType(), 0) then
  begin
    if not CryptAcquireContext(context, nil, nil, GetAvailableProviderType(), CRYPT_NEWKEYSET) then
    begin
      raise EXadesMessageError.Create(GetLastErrorText('CryptAcquireContext'));
    end;
  end;
  try
    if not CryptCreateHash(context, CALG_SHA1, 0, 0, hash) then
    begin
      raise EXadesMessageError.Create(GetLastErrorText('CryptCreateHash'));
    end;
    data := TMemoryStream.Create();
    try
      if not CryptHashData(hash, Pointer(AXml), Length(AXml), 0) then
      begin
        raise EXadesMessageError.Create(GetLastErrorText('CryptHashData'));
      end;
      dwordSize := SizeOf(cardinal);
      if not CryptGetHashParam(hash, HP_HASHSIZE, @hashSize, dwordSize, 0) then
      begin
        raise EXadesMessageError.Create(GetLastErrorText('CryptGetHashParam'));
      end;
      data.setSize(hashSize);
      if not CryptGetHashParam(hash, HP_HASHVAL, data.memory, hashSize, 0) then
      begin
        raise EXadesMessageError.Create(GetLastErrorText('CryptGetHashParam'));
      end;
      SetLength(Result, hashSize);
      system.Move(data.memory^, Pointer(Result)^, hashSize);
    finally
      data.Free();
      CryptDestroyHash(hash);
    end;
  finally
    CryptReleaseContext(context, 0);
  end;
end;

*)



(*
function TXades.GetSignatureValue(ACertificate: TCertificate; const AXml: string): string;
var
  context: HCRYPTPROV;
  hash: HCRYPTHASH;
  sigData: TMemoryStream;
  sigSize: DWORD;
begin
//  context:=ACertificate.getproviderHandle;
  context:=ACertificate.aquireCOntext;;
  MessageDlg('start siv '+inttostr(context), mtError, [mbOK], 0);

  try
    if not CryptCreateHash(context, CALG_SHA1, 0, 0, hash) then
    begin
      raise EXadesMessageError.Create(GetLastErrorText('CryptCreateHash'));
    end;
    sigData := TMemoryStream.Create();
    try
      if not CryptHashData(hash, Pointer(AXml), Length(AXml), 0) then
      begin
        raise EXadesMessageError.Create(GetLastErrorText('CryptHashData'));
      end;
      if not CryptSignHash(hash, AT_KEYEXCHANGE, nil, 0, nil, sigSize) then
      begin
        raise EXadesMessageError.Create(GetLastErrorText('CryptSignHash'));
      end;
      sigData.setsize(sigSize);
      if not CryptSignHash(hash, AT_KEYEXCHANGE, nil, 0, sigData.memory, sigSize) then
      begin
        raise EXadesMessageError.Create(GetLastErrorText('CryptSignHash'));
      end;
      SetLength(Result, sigSize);
      system.Move(sigData.memory^, Pointer(Result)^, sigSize);
      result:=reversedString(result);
    finally
      sigData.Free();
      CryptDestroyHash(hash);
    end;
  finally
//    ACertificate.releaseContext(context);
//  MessageDlg('stop siv '+result, mtError, [mbOK], 0);
  end;
end;
*)

function tXades.getCertificate;
begin
  result:=fCertificate;
end;

end.
