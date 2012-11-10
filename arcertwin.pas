{$IFDEF XHTML}
 {%main htarcert}
 {$DEFINE LOLE}
{$ELSE}

{.$I start.inc}

unit arcertwin;
{$H+}

interface
uses
  Windows,
  Messages, SysUtils, Classes,
  arcert,
  wpstring,
  wpdate,
  EncdDecd,
//      sha1,
  synacode,
  jwawincrypt;
{$ENDIF}


  function enumCertlist(glos : boolean;const storeName: ansistring):ansiString;
  function findCert(glos : boolean;const storeName: ansistring;const aSerial: ansiString):tCertificate;
  function enumCertlistOld(glos : boolean;const storeName: ansistring):ansiString;

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

    tCertificateWin = class(tCertificate)
  private
    FCertContext: PCCERT_CONTEXT;
    fcontext: HCRYPTPROV;
    procedure GetCertInfo;
    function getIssuerName : string;
    procedure getCertEncode;
   public
    storePos : integer;
    constructor Create(ACertContext: PCCERT_CONTEXT);
    destructor Destroy; override;
    property Context: PCCERT_CONTEXT read FCertContext;

    function getProviderHandle:HCRYPTPROV;
    function GetSignatureValue(const AXml: string): string;override;
    function GetDigestValue(const AXml: string): string;override;
    class function GetLastErrorText(const AFuncName: string): string;
    function GetAvailableProviderType: cardinal;
    function aquireContext:HCRYPTPROV;
    procedure releaseContext(aProv :HCRYPTPROV) ;
    function enumerateProperty:ansiString;
    end;

  tCertStore = class
    err   : ansiString;
    hStore: HCERTSTORE;
    lastError : int64;

    constructor create(aName : string);
    procedure close;
    function enum(var aCertContext : PCCERT_CONTEXT):boolean;
    destructor destroy;override;
//    class function GetLastErrorText(const AFuncName: string): string;
  end;




implementation
const

 CRYPT_E_NOT_FOUND             =   ($80092004);//2148081668
 CRYPT_E_SELF_SIGNED           =   ($80092007);


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


function ConvertFileTimeToDateTime(AFileTime: TFileTime): TDateTime;
var
  lpSystemTime: TSystemTime;
  LocalFileTime: TFileTime;
begin
  if FileTimeToLocalFileTime(AFileTime, LocalFileTime) then
  begin
    FileTimeToSystemTime(LocalFileTime, lpSystemTime);
    Result := SystemTimeToDateTime(lpSystemTime);
  end else
  begin
    Result := 0;
  end;
end;

function LocalTimeToGlobalTime(ATime: TDateTime): TDateTime;
var
  ST: TSystemTime;
  FT: TFileTime;
begin
  DateTimeToSystemTime(ATime, ST);
  SystemTimeToFileTime(ST, FT);
  LocalFileTimeToFileTime(FT, FT);
  FileTimeToSystemTime(FT, ST);
  Result := SystemTimeToDateTime(ST);
end;


constructor tCertStore.create;
begin
   hStore := CertOpenSystemStore(0, PChar(aName));
end;

procedure tCertStore.close;
begin
   CertCloseStore(hStore, {0} CERT_CLOSE_STORE_CHECK_FLAG);

end;

destructor tCertStore.destroy;
begin
  close;
  inherited destroy;
end;

function tCertStore.enum;
begin
     aCertContext := CertEnumCertificatesInStore(hStore, aCertContext);
     if aCertContext=nil then begin
      case GetLastError of
      CRYPT_E_NOT_FOUND  : err := 'not found';
      ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
      ERROR_NOT_ENOUGH_MEMORY: err := 'ERROR_NOT_ENOUGH_MEMORY';
      longword(NTE_BAD_FLAGS): err := 'NTE_BAD_FLAGS';
      else err:=' nne';
      end;
      result:=false;
//      result:=inttostr(getLastError)+err;
     end else result:=true;

end;

(*
class function TCertStore.GetLastErrorText(const AFuncName: string): string;
var
  code: cardinal;
  Len: Integer;
  Buffer: array[0..255] of Char;
begin
  code := GetLastError();
  Len := FormatMessage(FORMAT_MESSAGE_FROM_HMODULE or FORMAT_MESSAGE_FROM_SYSTEM,
    Pointer(GetModuleHandle('crypt32.dll')), code, 0, Buffer, SizeOf(Buffer), nil);
  while (Len > 0) and (Buffer[Len - 1] in [#0..#32, '.']) do Dec(Len);
  SetString(Result, Buffer, Len);
  if (Trim(Result) = '') then
  begin
    Result := Format('%s error - %d', [AFuncName, code]);
  end;
end;
 *)

function tCertificateWin.GetDigestValue(const AXml: string): string;
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
      raise ECertificateError.Create(GetLastErrorText('CryptAcquireContext'));
    end;
  end;
  try
    if not CryptCreateHash(context, CALG_SHA1, 0, 0, hash) then
    begin
      raise ECertificateError.Create(GetLastErrorText('CryptCreateHash'));
    end;
    data := TMemoryStream.Create();
    try
      if not CryptHashData(hash, Pointer(AXml), Length(AXml), 0) then
      begin
        raise ECertificateError.Create(GetLastErrorText('CryptHashData'));
      end;
      dwordSize := SizeOf(cardinal);
      if not CryptGetHashParam(hash, HP_HASHSIZE, @hashSize, dwordSize, 0) then
      begin
        raise ECertificateError.Create(GetLastErrorText('CryptGetHashParam'));
      end;
      data.setSize(hashSize);
      if not CryptGetHashParam(hash, HP_HASHVAL, data.memory, hashSize, 0) then
      begin
        raise ECertificateError.Create(GetLastErrorText('CryptGetHashParam'));
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




function enumcertList;
var
  store : tCertStore;
  cert  : tCertificateWin;
  hConText: PCCERT_CONTEXT;

begin
  result:='';
  store:=tCertStore.create(storeName);
  hContext:=nil;
  while store.enum(hContext) do begin
    cert:=tCertificateWin.create(hContext);
    result:=result+cert.serialNumberDec+#8+pad(cert.issuerName,33)+' '+pad(cert.issuedto,28)+date4st(cert.ValidTo)+' '+cert.serialNumberHex+#10;
    cert.Free
  end;

  store.free;
end;

function findCert;
var
  store : tCertStore;
  cert  : tCertificateWin;
  hConText: PCCERT_CONTEXT;
begin

  result:=nil;
  if aSerial='' then exit;
  store:=tCertStore.create(storeName);
  hContext:=nil;
  try
  while store.enum(hContext) do begin
    cert:=tCertificateWin.create(hContext);
    if cert.serialNumberDec=aSerial then begin
      result:=cert;
      exit;
    end ;
    cert.Free
  end;
  finally
  store.free;
  end;

end;

function EnumCertlISTOld;
var
   hStore: HCERTSTORE;
   pCertConText: PCCERT_CONTEXT;
   dwPropId: LONGwORD;

   cbData: LONGword;
   pProvInfo: PCRYPT_KEY_PROV_INFO;
   pHashInfo : PCRYPT_HASH_BLOB;
   cspHash : ansiString;
   CspName: widestring;
   ContainerName: widestring;
    nameBLOB: CERT_NAME_BLOB;
    encType: DWORD;
    nameString: PChar;
    err: string;
    fSize : integer;
    aCert  : ansistring;


    function str64(var aaa : CERT_NAME_BLOB):string;
    var
      s : string;
      i : integer;
    begin
      s:='';
      for i:= 0 to aaa.cbData-1 do begin
        s:=s+char(pchar(aaa.Pbdata)[i]);
      end;
      result:=s;
    end;
    function hash64(st : integer;pt : pointer):string;
    var
      s : string;
      i : integer;
    begin
      s:='';
      for i:= 0 to st-1 do begin
        s:=s+inttohex(byte(pchar(pt)[i]),2)+' ';
      end;
      result:=s;
    end;
    function bit64(var aaa : CERT_NAME_BLOB):string;
    var
      s : string;
      i : integer;
    begin
      s:='';
      for i:= 0 to aaa.cbData-1 do begin
        s:=s+inttohex(byte(pchar(aaa.Pbdata)[i]),2)+' ';
      end;
//      move(aaa,s[1],8);
      result:=s;
    end;

begin
   { open store }
//  RepMemo.Lines.Add('Contents  ' + storeName);
   hStore := CertOpenSystemStore(0, PChar(storeName));
nameString := StrAlloc(512);
encType := PKCS_7_ASN_ENCODING or X509_ASN_ENCODING;

   try
     { read first certificate }
     pCertContext := CertEnumCertificatesInStore(hStore, nil);
     if pCertContext=nil then begin
      case GetLastError of
      CRYPT_E_NOT_FOUND  : err := 'not found';
      ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
      ERROR_NOT_ENOUGH_MEMORY: err := 'ERROR_NOT_ENOUGH_MEMORY';
      longword(NTE_BAD_FLAGS): err := 'NTE_BAD_FLAGS';
      else err:=' nne';
      end;
      result:=inttostr(getLastError)+err;
      exit;
     end;


     while pCertContext <> nil do    begin
        aCert:=#8;
        nameBLOB := pCertContext^.pCertInfo^.Subject;
        fsize := CertNameToStr(encType, @nameBlob, CERT_SIMPLE_NAME_STR,       nameString, 512);
        aCert:=aCert+nameString+'|';
        nameBLOB := pCertContext^.pCertInfo^.Issuer;

        fsize := CertNameToStr(encType, @nameBlob, CERT_SIMPLE_NAME_STR,nameString, 512);
        aCert:=aCert+nameString+'|';
        aCert:=aCert+bit64(pCertContext^.pCertInfo^.SerialNumber)+'|';

  {
       CertGetNameStringA(pCertContext,4,0,nil,nameString, 512);
         RepMemo.Lines.Add('*4* '+nameString);
       CertGetNameStringA(pCertContext,3,0,nil,nameString, 512);
         RepMemo.Lines.Add('*3* '+nameString);
       CertGetNameStringA(pCertContext,2,0,nil,nameString, 512);
         RepMemo.Lines.Add('*2* '+nameString);
       CertGetNameStringA(pCertContext,1,0,nil,nameString, 512);
         RepMemo.Lines.Add('*1* '+nameString);
}
       CspName := '';
       ContainerName := '';
       cspHash:='';
       { loop over propids until we find CERT_KEY_PROV_INFO_PROPID }
       dwPropID := CertEnumCertificateContextProperties(pCertContext, 0);
       while dwPropid <> 0 do       begin
         if dwPropId= CERT_FRIENDLY_NAME_PROP_ID then begin
//            RepMemo.Lines.Add('*nameid* ');
         end;
         if dwPropID=CERT_SHA1_HASH_PROP_ID then begin
//            RepMemo.Lines.Add('*sha1* ');
           if CertGetCertificateContextProperty(
             pCertContext,             dwPropID,nil,cbData) then
           begin
             GetMem(pHashInfo, cbData);
             try
               if CertGetCertificateContextProperty(
                 pCertContext,
                 dwPropID,
                 pHashInfo,cbData) then            begin
                   cspHash:=hash64(cbData,pHashInfo);
                   {
                   fsize := CertNameToStr(encType, pointer(pHashInfo), CERT_SIMPLE_NAME_STR,
                          nameString, 512);
                   RepMemo.Lines.Add(inttohex(pHashInfo^.cbData,4));
                   }
                 end;
             finally
               FreeMem(pHashInfo);
             end;
           end;

         end;

         if CERT_KEY_PROV_INFO_PROP_ID = dwPropID then
         begin
           { got it, extract the provider name }
           if CertGetCertificateContextProperty(
             pCertContext,
             dwPropID,
             nil,cbData) then
           begin
             GetMem(pProvInfo, cbData);
             try
               if CertGetCertificateContextProperty(
                 pCertContext,
                 dwPropID,
                 pProvInfo,cbData) then            begin
                 CspName :=widestring(WideCharToString(pProvInfo.pwszProvName));
                 ContainerName :=widestring(WideCharToString(pProvInfo.pwszContainerName));
                 end;
             finally
               FreeMem(pProvInfo);
             end;
           end;
         end;
         { get next propid }
         dwPropID := CertEnumCertificateContextProperties(pCertContext,   dwPropID);
       end;
         aCert:=aCert+cspHash+#8;
       pCertContext := CertEnumCertificatesInStore(hStore, pCertContext);
       aCert:=aCert+#13;
       result:=result+aCert;
     end;
   finally
     CertCloseStore(hStore, {0} CERT_CLOSE_STORE_CHECK_FLAG);
   end;

end;


constructor tCertificateWin.Create(ACertContext: PCCERT_CONTEXT);
begin
  inherited Create();
  FCertContext := CertDuplicateCertificateContext(ACertContext);
  GetCertInfo();
//  enumerateProperty;
end;

destructor tCertificateWin.Destroy;
begin
  CertFreeCertificateContext(FCertContext);
  inherited Destroy();
end;
function tCertificateWin.getProviderHandle;
var
    cbSize: DWORD;
    dwPropID :DWord;

begin
     cbSize:=sizeof(result);
//     dwPropID:=CERT_KEY_PROV_HANDLE_PROP_ID;
     dwPropId:=CERT_KEY_CONTEXT_PROP_ID;
    if CertGetCertificateContextProperty(
            fCertContext,             dwPropID,nil,cbSize) then begin

    if not CertGetCertificateContextProperty(FCertContext,
      dwPropid, @result, cbSize) then result:=$FFFFFFFF;
    end;

end;


procedure tCertificateWin.getCertEncode;
var
  cer : ansiString;
  i   : integer;
begin
      setLength(cer,fCertContext^.cbCertEncoded);
      move(fCertContext^.pbCertEncoded^,cer[1],fCertContext^.cbCertEncoded);
      f509Digest:=encodeString(sha1(cer));
      f509Data:=encodestring(cer);
      i:=64;
      while i<length(f509Data) do begin
        insert(#10,f509Data,i);
        inc(i,65);
      end;

end;

procedure tCertificateWin.GetCertInfo();
  function GetDecodedName(AType, AFlags: Integer): string;
  var
    len: Integer;
    p: PChar;
  begin
    len := CertGetNameStringA(FCertContext, AType, AFlags, nil, nil, 0);
    if (len > 1) then
    begin
      GetMem(p, len);
      CertGetNameStringA(FCertContext, AType, AFlags, nil, p, len);
      SetString(Result, p, len - 1);
      FreeMem(p);
    end else
    begin
      Result := '';
    end;
  end;

  function GetBLOBToBin(ABlob: CERT_NAME_BLOB): string;
  var
    i: Integer;
    p: Pointer;
  begin
    Result := '';
    for i := ABlob.cbData - 1 downto 0 do
    begin
      p := Pointer(Integer(ABlob.pbData) + i);
      result:=result+char(byte(p^));
//      Result := Result + IntToHex(Byte(p^), 2);
    end;
  end;
  {
  function GetBLOBToDec(ABlob: CERT_NAME_BLOB): string;
  var
    i: Integer;
    ll : int64;
    p: Pointer;
  begin
    ll:=0;
    for i := ABlob.cbData - 1 downto 0 do
    begin
      p := Pointer(Integer(ABlob.pbData) + i);
      ll:=ll shl 8+Byte(p^);
    end;
    result:=inttostr(ll);
  end;
  }
  function GetBinToHex(ABlob:CRYPT_BIT_BLOB): string;
  var
    i: Integer;
    p: Pointer;
  begin
    Result := '';
    for i := ABlob.cbData - 1 downto 0 do
    begin
      p := Pointer(Integer(ABlob.pbData) + i);
      Result := Result + IntToHex(Byte(p^), 2);
    end;
  end;

  function GetFriendlyName(dwPropId :dword): string;
  var
    cbSize: DWORD;
    p: PWideChar;
  begin
    Result := '';
    cbSize := 0;
    if not CertGetCertificateContextProperty(FCertContext,
      dwPropId, nil, cbSize) then Exit;
    if (cbSize < 1) then Exit;

    GetMem(p, cbSize);
    try
      CertGetCertificateContextProperty(FCertContext,dwPropId , p, cbSize);
      Result := string(system.Copy(p, 1, cbSize));
    finally
      FreeMem(p);
    end;
  end;
    function str64(var aaa : CERT_NAME_BLOB):string;
    var
      s : string;
      i : integer;
    begin
      s:='';
      for i:= 0 to aaa.cbData-1 do begin
        s:=s+char(pchar(aaa.Pbdata)[i]);
      end;
      result:=s;
    end;


begin
  FIssuedBy := GetDecodedName(CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);
  FIssuedTo := GetDecodedName(CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);
  FValidFrom := ConvertFileTimeToDateTime(FCertContext^.pCertInfo.NotBefore);
  FValidTo := ConvertFileTimeToDateTime(FCertContext^.pCertInfo.NotAfter);
  fIssuerName:=getIssuerName;
  FSerialNumber := GetBLOBToBin(FCertContext^.pCertInfo.SerialNumber);
  fSignatureAlgorithm:=FCertContext^.pCertInfo.SignatureAlgorithm.pszObjId^;
  fIssuerUniqueId:= GetBinToHex(FCertContext^.pCertInfo.IssuerUniqueId);
  fSubjectUniqueId:= GetBinToHex(FCertContext^.pCertInfo.SubjectUniqueId);
  FFriendlyName := GetFriendlyName(CERT_FRIENDLY_NAME_PROP_ID);
  FSHA1 := GetFriendlyName(CERT_SHA1_HASH_PROP_ID);
  getCertEncode;
end;

function tCertificateWin.getIssuerName;
var
    nameBLOB: CERT_NAME_BLOB;
    encType: DWORD;
    nameString: PChar;
    fSize : integer;

begin
      nameString := StrAlloc(512);
      encType := PKCS_7_ASN_ENCODING or X509_ASN_ENCODING;
      nameBLOB := fCertContext^.pCertInfo^.Issuer;
      fsize := CertNameToStr(encType, @nameBlob, CERT_X500_NAME_STR+CERT_NAME_STR_REVERSE_FLAG,
           nameString, 512);
      if fSize>0 then result:=nameString
      else result:='';
      strDispose(nameString);


end;


function tCertificateWin.aquireContext;
var
  keySpec: DWORD;
  callerFree: BOOL;

begin
  if (not CryptAcquireCertificatePrivateKey(Context,
    CRYPT_ACQUIRE_COMPARE_KEY_FLAG, nil, result, @keySpec, @callerFree))
    or
    (not callerFree) then
  begin
    raise ECertificateError.Create('CryptAcquireCertificatePrivateKey');
  end;

end;

procedure tCertificateWin.releaseContext;
begin
    CryptReleaseContext(aprov, 0);

end;
function tCertificateWin.enumerateProperty;
var
   dwPropId: LONGwORD;
begin
  result:='';
  dwPropID := CertEnumCertificateContextProperties(fCertContext, 0);
  while dwPropid <> 0 do       begin
     case dwPropId of
      CERT_SHA1_HASH_PROP_ID : result:=result+'SHA1_HASH_PROP|';
      CERT_KEY_IDENTIFIER_PROP_ID : result:=result+'KEY_IDENTIFIER_PROP|';
      CERT_KEY_CONTEXT_PROP_ID: result:=result+'KEY CONTEXT PROP|'
     else result:=result+inttostr(dwPropId)+'|';
     end;


     dwPropID := CertEnumCertificateContextProperties(fCertContext,   dwPropID);
  end;
end;


class function TCertificateWin.GetLastErrorText(const AFuncName: string): string;
var
  code: DWORD;
  Len: Integer;
  Buffer: array[0..255] of Char;
begin
  code := GetLastError();
  Len := FormatMessage(FORMAT_MESSAGE_FROM_HMODULE or FORMAT_MESSAGE_FROM_SYSTEM,
    Pointer(GetModuleHandle('crypt32.dll')), code, 0, Buffer, SizeOf(Buffer), nil);
  while (Len > 0) and (Buffer[Len - 1] in [#0..#32, '.']) do Dec(Len);
  SetString(Result, Buffer, Len);
  if (Trim(Result) = '') then
  begin
    Result := Format('%s error - %d', [AFuncName, code]);
  end;
end;

function TCertificateWin.GetAvailableProviderType: cardinal;
var
  i, len: cardinal;
begin
  i := 0;
  while CryptEnumProviderTypes(i, nil, 0, Result, nil, len) do
  begin
    if (Result in [PROV_RSA_FULL, PROV_DSS, PROV_RSA_SCHANNEL,
      PROV_DSS_DH, PROV_DH_SCHANNEL, PROV_RSA_AES]) then Exit;
    Inc(i);
  end;
  Result := PROV_RSA_FULL;
end;


function TCertificateWin.GetSignatureValue(const AXml: string): string;
var
  xProv: HCRYPTPROV;
  hash: HCRYPTHASH;
  sigData: TMemoryStream;
  sigSize, keySpec: DWORD;
  callerFree: BOOL;
begin

  if (not CryptAcquireCertificatePrivateKey(Context,
    CRYPT_ACQUIRE_COMPARE_KEY_FLAG, nil, xProv, @keySpec, @callerFree))
    or
    (not callerFree) then
  begin
//    result:='1234566';
//    exit;
    raise ECertificateError.Create(GetLastErrorText('CryptAcquireCertificatePrivateKey'));
  end;
  try
    if not CryptCreateHash(xprov, CALG_SHA1, 0, 0, hash) then
    begin
      raise ECertificateError.Create(GetLastErrorText('CryptCreateHash'));
    end;
    sigData := TMemoryStream.Create();
    try
      if not CryptHashData(hash, Pointer(AXml), Length(AXml), 0) then
      begin
        raise ECertificateError.Create(GetLastErrorText('CryptHashData'));
      end;
      if not CryptSignHash(hash, AT_KEYEXCHANGE, nil, 0, nil, sigSize) then
      begin
        raise ECertificateError.Create(GetLastErrorText('CryptSignHash'));
      end;
      sigData.setSize(sigSize);
      if not CryptSignHash(hash, AT_KEYEXCHANGE, nil, 0, sigData.memory, sigSize) then
      begin
        raise ECertificateError.Create(GetLastErrorText('CryptSignHash'));
      end;
      SetLength(Result, sigSize);
      system.Move(sigData.memory^, Pointer(Result)^, sigSize);
      result:=reversedString(result);

    finally
      sigData.Free();
      CryptDestroyHash(hash);
    end;
  finally
    CryptReleaseContext(xProv, 0);
  end;
end;


(*

function tCertificate.GetKeySize: Integer;
var
  Len: LongInt;
  Res: BOOL;
begin
  Result := FKeySize;
  if Result <= 0 then begin
    Len := SizeOf(Result);
    // This will fail for signature only keys:
    Res := CryptGetKeyParam(FKeyHandle,KP_BLOCKLEN,@Result,Len,0);
    if not Res then
      Result := 0
    else
      FKeySize := Result;
  end;
end;

function TCertificate.GetUserKey(KeySpec: Integer): Boolean;
begin
  if (KeySpec = FKeySpec) and (FKeyHandle <> 0) and (FStoreHandle <> 0) then begin
    Result := True;
    Exit;
  end;
  if FKeyHandle <> 0 then
    Check(CryptDestroyKey(FKeyHandle));
  FKeyHandle := 0;
  FKeySpec := 0;
  Result := Check(CryptGetUserKey(FStoreHandle,KeySpec,FKeyHandle));
  if Result then
    FKeySpec := KeySpec;
end;

*)


end.
