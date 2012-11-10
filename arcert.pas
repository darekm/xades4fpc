{.$IFDEF XHTML}
 {%main htarcert}
{.$ELSE}

{.$I start.inc}

unit arcert;
{$H+}

interface
uses
  Classes,
  kom2,
//  Graphics,
//  int128,
  SysUtils;
//  strutil,
  //wpstring,
//      EncdDecd;
//      synacode,
{.$ENDIF}

  type
  THashAlgorithm = ({$IFDEF SHA1}     haSHA1     {$ELSE}haReserved0{$ENDIF},
                    {$IFDEF MD5}      haMD5      {$ELSE}haReserved1{$ENDIF},
                    {$IFDEF RIPEMD160}haRipeMD160{$ELSE}haReserved2{$ENDIF},
                    {$IFDEF SHA256}   haSHA256   {$ELSE}haReserved3{$ENDIF},
                    {$IFDEF SHA512}   haSHA384   {$ELSE}haReserved4{$ENDIF},
                    {$IFDEF SHA512}   haSHA512   {$ELSE}haReserved5{$ENDIF},
                    {$IFDEF MD2}      haMD2      {$ELSE}haReserved6{$ENDIF},
                    {$IFDEF SHA256}   haSHA224   {$ELSE}haReserved7{$ENDIF},
                    haNull,
                    haDefault);
  TSignEncoding = ({$IFDEF SHA1_OR_RIPEMD160}
                   seEMSA2,      // As defined in P1363
                   {$ELSE  SHA1_OR_RIPEMD160}
                   seReserved0,
                   {$ENDIF SHA1_OR_RIPEMD160}
                   seEMSA3,      // PKCS#1v1.5
                   seEMSA4,      // PKCS#1v2.1 (RSASSA-PSS)
                   {$IFDEF SHA1_AND_MD5}
                   seEMSA_TLS    // TLS (PKCS#1v1.5 with no hash identifier and
                                 //      two digest values)
                   {$ELSE  SHA1_AND_MD5}
                   seReserved3
                   {$ENDIF SHA1_AND_MD5}
                   );


  type

  tCertificate = class
  protected
    FIssuedTo: string;
    FEmail: string;
    FIssuedBy: string;
    FIssuerName: string;
    FValidTo: TDateTime;
    FValidFrom: TDateTime;
    FSerialNumber: string;
    fIssuerUniqueID : string;
    fSubjectUniqueID : string;
    fSignatureAlgorithm : string;
    FFriendlyName: string;
    fSHA1    : string;
    f509Data: string;
    f509Digest : string;
    function getSerialNumberDec:string;
    function getSerialNumberHex:string;

   public
    storePos : integer;
    property IssuedTo: string read FIssuedTo;
    property IssuedBy: string read FIssuedBy;
    property FriendlyName: string read FFriendlyName;
    property Email: string read FEmail;
    property ValidFrom: TDateTime read FValidFrom;
    property ValidTo: TDateTime read FValidTo;
    property SerialNumberHex: string read getSerialNumberHex;
    property SerialNumberDec: string read getSerialNumberDec;
    property XSHA1: string read FSHA1;
    property signatureAlgorith : string read fSignatureAlgorithm;
    property IssuerUniqueID : string read fIssuerUniqueId;
    property issuerName : string read fIssuerName;
    property X509Data : ansistring read f509Data;

//    function getProviderHandle:HCRYPTPROV;
    function GetSignatureValue(const AXml: string): string;virtual;
    function GetDigestValue(const AXml: string): string;virtual;
    property x509Digest:ansistring read f509Digest;
//    class function GetLastErrorText(const AFuncName: string): string;
    function allName : ansiString;
    function fullname : ansiString;
    end;


type
  ECertificateError = class(Exception);

implementation
const

 CRYPT_E_NOT_FOUND             =   ($80092004);//2148081668
 CRYPT_E_SELF_SIGNED           =   ($80092007);





{
constructor tCertificate.Create(ACertContext: PCCERT_CONTEXT);
begin
  inherited Create();
  FCertContext := CertDuplicateCertificateContext(ACertContext);
  GetCertInfo();
end;

destructor tCertificate.Destroy;
begin
  CertFreeCertificateContext(FCertContext);
  inherited Destroy();
end;
}
function tCertificate.allname;
begin
  result:='issuedBy:'+fIssuedBy+#10;
  result:=result+'issuedTo:'+fIssuedTo+#10;
  result:=result+'issuerName:'+fIssuerName+#10;
  result:=result+'serialnumber:'+fSerialNumber+#10;
  result:=result+'subjectunique:'+fSubjectUniqueID+#10;
  result:=result+'friendlyName:'+fFriendlyName+#10;
  result:=result+'sha1:'+fsha1;
end;

function tCertificate.fullname;
begin
  result:=issuerName+ '  : '+issuedto;
end;

function tCertificate.getSerialNumberDec;
begin
  result:=BinToDec(fSerialNumber);
end;
function tCertificate.getSerialNumberHex;
begin
  result:=BinToHEX(fSerialNumber);
end;
function tCertificate.GetSignatureValue;
begin
  result:='';
end;
function tCertificate.GetDigestValue;
begin
  result:='';
end;


end.
