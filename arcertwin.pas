{****************************************************************************
*                                                                           *
*                                                            *
*                                                                           *
*                                                                           *
* Language:             FPC Pascal v2.2.0+ / Delphi 6+                      *
*                                                                           *
* Required switches:    none                                                *
*                                                                           *
* Author:               Dariusz Mazur                                       *
* Date:                 20.01.2010                                          *
* Version:              0.9                                                 *
* Licence:              MPL or GPL
*                                                                           *
*        Send bug reports and feedback to  darekm @@ emadar @@ com          *
*   You can always get the latest version/revision of this package from     *
*                                                                           *
*           http://www.emadar.com/fpc/lockfree.htm                          *
*                                                                           *
*                                                                           *
* Description:  Cert component to hangle Certificate store                  *
*               proposed by Dariusz Mazur                                   *
* caution : if You set too small size of array and store data excess size   *
*           of queue data will be lost                                      *
*                                                                           *
*  This program is distributed in the hope that it will be useful,          *
*  but WITHOUT ANY WARRANTY; without even the implied warranty of           *
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                     *
*                                                                           *
*                                                                           *
*****************************************************************************
*                      BEGIN LICENSE BLOCK                                  *

The contents of this file are subject to the Mozilla Public License
Version 1.1 (the "License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at
http://www.mozilla.org/MPL/

Software distributed under the License is distributed on an "AS IS" basis,
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for
the specific language governing rights and limitations under the License.

The Original Code is: flqueue.pas, released 20.01.2008.
The Initial Developer of the Original Code is Dariusz Mazur


Alternatively, the contents of this file may be used under the terms of the
GNU General Public License Version 2 (the "GPL"), in which case
the provisions of the GPL are applicable instead of those above.
If you wish to allow use of your version of this file only under the terms
of the GPL and not to allow others to use your version of this file
under the MPL, indicate your decision by deleting the provisions above and
replace them with the notice and other provisions required by the GPL.
If you do not delete the provisions above, a recipient may use your version
of this file under either the MPL or the GPL.

*                     END LICENSE BLOCK                                     * }



{$IFDEF XHTML}
{%main htarcert}
 {$DEFINE LOLE}
{$ELSE}


unit arcertwin;

{$H+}

interface

uses
  Windows,
  Messages,
  SysUtils,
  Classes,
  arcert,
  EncdDecd,
  synacode,
  jwawincrypt;

{$ENDIF}


function enumCertList(glos: boolean; const aStoreName: string): string;
function findCert(glos: boolean; const aStoreName: string;
  const aSerial: string): tCertificate;
function enumCertListOld(glos: boolean; const storeName: string): string;

const
  storeName = 'MY';

type

  tCertificateWin = class(tCertificate)
  private
    FCertContext: PCCERT_CONTEXT;
    procedure GetCertInfo;
    function getIssuerName: string;
    procedure getCertEncode;
  public
    storePos: integer;
    constructor Create(ACertContext: PCCERT_CONTEXT);
    destructor Destroy; override;
    property Context: PCCERT_CONTEXT read FCertContext;

    function getProviderHandle: HCRYPTPROV;
    function GetSignatureValue(const AXml: string): string; override;
    function GetDigestValue(const AXml: string): string; override;
    class function GetLastErrorText(const AFuncName: string): string;
    function GetAvailableProviderType: cardinal;
    function aquireContext: HCRYPTPROV;
    procedure releaseContext(aProv: HCRYPTPROV);
    function enumerateProperty: string;
  end;

  tCertStore = class
    err: string;
    hStore: HCERTSTORE;
    lastError: int64;

    constructor Create(aName: string);
    procedure Close;
    function enum(var aCertContext: PCCERT_CONTEXT): boolean;
    destructor Destroy; override;
  end;




implementation

const

  CRYPT_E_NOT_FOUND = ($80092004);//2148081668
  CRYPT_E_SELF_SIGNED = ($80092007);


function ReversedString(const AStr: string): string;
var
  I: integer;
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
  lpSystemTime:  TSystemTime;
  LocalFileTime: TFileTime;
begin
  if FileTimeToLocalFileTime(AFileTime, LocalFileTime) then
  begin
    FileTimeToSystemTime(LocalFileTime, lpSystemTime);
    Result := SystemTimeToDateTime(lpSystemTime);
  end
  else
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


constructor tCertStore.Create;
begin
  hStore := CertOpenSystemStore(0, PChar(aName));
end;

procedure tCertStore.Close;
begin
  CertCloseStore(hStore, {0} CERT_CLOSE_STORE_CHECK_FLAG);

end;

destructor tCertStore.Destroy;
begin
  Close;
  inherited Destroy;
end;

function tCertStore.enum;
begin
  aCertContext := CertEnumCertificatesInStore(hStore, aCertContext);
  if aCertContext = nil then
  begin
    case GetLastError of
      CRYPT_E_NOT_FOUND: err := 'not found';
      ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
      ERROR_NOT_ENOUGH_MEMORY: err := 'ERROR_NOT_ENOUGH_MEMORY';
      longword(NTE_BAD_FLAGS): err := 'NTE_BAD_FLAGS';
      else
        err := ' nne';
    end;
    Result := False;
    //      result:=inttostr(getLastError)+err;
  end
  else
    Result := True;

end;


function tCertificateWin.GetDigestValue(const AXml: string): string;
var
  context: HCRYPTPROV;
  hash:    HCRYPTHASH;
  Data:    TmemoryStream;
  hashSize, dwordSize: cardinal;
begin
  if not CryptAcquireContext(context, nil, nil, GetAvailableProviderType(), 0) then
  begin
    if not CryptAcquireContext(context, nil, nil, GetAvailableProviderType(),
      CRYPT_NEWKEYSET) then
    begin
      raise ECertificateError.Create(GetLastErrorText('CryptAcquireContext'));
    end;
  end;
  try
    if not CryptCreateHash(context, CALG_SHA1, 0, 0, hash) then
    begin
      raise ECertificateError.Create(GetLastErrorText('CryptCreateHash'));
    end;
    Data := TMemoryStream.Create();
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
      Data.setSize(hashSize);
      if not CryptGetHashParam(hash, HP_HASHVAL, Data.memory, hashSize, 0) then
      begin
        raise ECertificateError.Create(GetLastErrorText('CryptGetHashParam'));
      end;
      SetLength(Result, hashSize);
      system.Move(Data.memory^, Pointer(Result)^, hashSize);
    finally
      Data.Free();
      CryptDestroyHash(hash);
    end;
  finally
    CryptReleaseContext(context, 0);
  end;
end;




function enumcertList;
var
  hConText: PCCERT_CONTEXT;

begin
  Result := '';
  hContext := nil;
  with tCertStore.Create(aStoreName) do
    try
      while enum(hContext) do
      begin
        with tCertificateWin.Create(hContext) do
          try
            Result := Result + serialNumberHEX + #8 + title + #10
          finally
            Free
          end;
      end;
    finally
      Free;
    end;
end;

function findCert;
var
  store:    tCertStore;
  cert:     tCertificateWin;
  hConText: PCCERT_CONTEXT;
begin

  Result := nil;
  if aSerial = '' then
    exit;
  store := tCertStore.Create(aStoreName);
  hContext := nil;
  try
    while store.enum(hContext) do
    begin
      cert := tCertificateWin.Create(hContext);
      if cert.serialNumberHEX = aSerial then
      begin
        Result := cert;
        exit;
      end;
      cert.Free;
    end;
  finally
    store.Free;
  end;

end;

function EnumCertListOld;
var
  hStore:   HCERTSTORE;
  pCertConText: PCCERT_CONTEXT;
  dwPropId: longword;

  cbData: longword;
  pProvInfo: PCRYPT_KEY_PROV_INFO;
  pHashInfo: PCRYPT_HASH_BLOB;
  cspHash: string;
  CspName: WideString;
  ContainerName: WideString;
  nameBLOB: CERT_NAME_BLOB;
  encType: DWORD;
  nameString: PChar;
  err:   string;
  fSize: integer;
  aCert: string;


  function str64(var aaa: CERT_NAME_BLOB): string;
  var
    s: string;
    i: integer;
  begin
    s := '';
    for i := 0 to aaa.cbData - 1 do
    begin
      s := s + char(PChar(aaa.Pbdata)[i]);
    end;
    Result := s;
  end;

  function hash64(st: integer; pt: pointer): string;
  var
    s: string;
    i: integer;
  begin
    s := '';
    for i := 0 to st - 1 do
    begin
      s := s + inttohex(byte(PChar(pt)[i]), 2) + ' ';
    end;
    Result := s;
  end;

  function bit64(var aaa: CERT_NAME_BLOB): string;
  var
    s: string;
    i: integer;
  begin
    s := '';
    for i := 0 to aaa.cbData - 1 do
    begin
      s := s + inttohex(byte(PChar(aaa.Pbdata)[i]), 2) + ' ';
    end;
    Result := s;
  end;

begin
  { open store }
  hStore := CertOpenSystemStore(0, PChar(storeName));
  nameString := StrAlloc(512);
  encType := PKCS_7_ASN_ENCODING or X509_ASN_ENCODING;

  try
    { read first certificate }
    pCertContext := CertEnumCertificatesInStore(hStore, nil);
    if pCertContext = nil then
    begin
      case GetLastError of
        CRYPT_E_NOT_FOUND: err := 'not found';
        ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
        ERROR_NOT_ENOUGH_MEMORY: err := 'ERROR_NOT_ENOUGH_MEMORY';
        longword(NTE_BAD_FLAGS): err := 'NTE_BAD_FLAGS';
        else
          err := ' nne';
      end;
      Result := IntToStr(getLastError) + err;
      exit;
    end;


    while pCertContext <> nil do
    begin
      aCert := #8;
      nameBLOB := pCertContext^.pCertInfo^.Subject;
      fsize := CertNameToStr(encType, @nameBlob, CERT_SIMPLE_NAME_STR,
        nameString, 512);
      aCert := aCert + nameString + '|';
      nameBLOB := pCertContext^.pCertInfo^.Issuer;

      fsize := CertNameToStr(encType, @nameBlob, CERT_SIMPLE_NAME_STR, nameString, 512);
      aCert := aCert + nameString + '|';
      aCert := aCert + bit64(pCertContext^.pCertInfo^.SerialNumber) + '|';

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
      cspHash := '';
      { loop over propids until we find CERT_KEY_PROV_INFO_PROPID }
      dwPropID := CertEnumCertificateContextProperties(pCertContext, 0);
      while dwPropid <> 0 do
      begin
        if dwPropId = CERT_FRIENDLY_NAME_PROP_ID then
        begin
          //            RepMemo.Lines.Add('*nameid* ');
        end;
        if dwPropID = CERT_SHA1_HASH_PROP_ID then
        begin
          //            RepMemo.Lines.Add('*sha1* ');
          if CertGetCertificateContextProperty(
            pCertContext, dwPropID, nil, cbData) then
          begin
            GetMem(pHashInfo, cbData);
            try
              if CertGetCertificateContextProperty(
                pCertContext, dwPropID,
                pHashInfo, cbData) then
              begin
                cspHash := hash64(cbData, pHashInfo);
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
            pCertContext, dwPropID, nil, cbData) then
          begin
            GetMem(pProvInfo, cbData);
            try
              if CertGetCertificateContextProperty(
                pCertContext, dwPropID,
                pProvInfo, cbData) then
              begin
                CspName := WideString(WideCharToString(pProvInfo.pwszProvName));
                ContainerName :=
                  WideString(WideCharToString(pProvInfo.pwszContainerName));
              end;
            finally
              FreeMem(pProvInfo);
            end;
          end;
        end;
        { get next propid }
        dwPropID := CertEnumCertificateContextProperties(pCertContext, dwPropID);
      end;
      aCert := aCert + cspHash + #8;
      pCertContext := CertEnumCertificatesInStore(hStore, pCertContext);
      aCert := aCert + #13;
      Result := Result + aCert;
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
end;

destructor tCertificateWin.Destroy;
begin
  CertFreeCertificateContext(FCertContext);
  inherited Destroy();
end;

function tCertificateWin.getProviderHandle;
var
  cbSize:   DWORD;
  dwPropID: DWord;

begin
  cbSize := sizeof(Result);
  //     dwPropID:=CERT_KEY_PROV_HANDLE_PROP_ID;
  dwPropId := CERT_KEY_CONTEXT_PROP_ID;
  if CertGetCertificateContextProperty(fCertContext,
    dwPropID, nil, cbSize) then
  begin

    if not CertGetCertificateContextProperty(FCertContext, dwPropid,
      @Result, cbSize) then
      Result := $FFFFFFFF;
  end;
end;


procedure tCertificateWin.getCertEncode;
var
  cer: string;
  i:   integer;
begin
  setLength(cer, fCertContext^.cbCertEncoded);
  move(fCertContext^.pbCertEncoded^, cer[1], fCertContext^.cbCertEncoded);
  f509Digest := encodeString(sha1(cer));
  f509Data := encodestring(cer);
  i := 64;
  while i < length(f509Data) do
  begin
    insert(#10, f509Data, i);
    Inc(i, 65);
  end;
end;

procedure tCertificateWin.GetCertInfo();

  function GetDecodedName(AType, AFlags: integer): string;
  var
    len: integer;
    p:   PChar;
  begin
    len := CertGetNameStringA(FCertContext, AType, AFlags, nil, nil, 0);
    if (len > 1) then
    begin
      GetMem(p, len);
      CertGetNameStringA(FCertContext, AType, AFlags, nil, p, len);
      SetString(Result, p, len - 1);
      FreeMem(p);
    end
    else
    begin
      Result := '';
    end;
  end;

  function GetBLOBToBin(ABlob: CERT_NAME_BLOB): string;
  var
    i: integer;
    p: Pointer;
  begin
    Result := '';
    for i := ABlob.cbData - 1 downto 0 do
    begin
      p := Pointer(integer(ABlob.pbData) + i);
      Result := Result + char(byte(p^));
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
  function GetBinToHex(ABlob: CRYPT_BIT_BLOB): string;
  var
    i: integer;
    p: Pointer;
  begin
    Result := '';
    for i := ABlob.cbData - 1 downto 0 do
    begin
      p := Pointer(integer(ABlob.pbData) + i);
      Result := Result + IntToHex(byte(p^), 2);
    end;
  end;

  function GetFriendlyName(dwPropId: dword): string;
  var
    cbSize: DWORD;
    p:      PWideChar;
  begin
    Result := '';
    cbSize := 0;
    if not CertGetCertificateContextProperty(FCertContext, dwPropId,
      nil, cbSize) then
      Exit;
    if (cbSize < 1) then
      Exit;

    GetMem(p, cbSize);
    try
      CertGetCertificateContextProperty(FCertContext, dwPropId, p, cbSize);
      Result := string(system.Copy(p, 1, cbSize));
    finally
      FreeMem(p);
    end;
  end;

  function str64(var aaa: CERT_NAME_BLOB): string;
  var
    s: string;
    i: integer;
  begin
    s := '';
    for i := 0 to aaa.cbData - 1 do
    begin
      s := s + char(PChar(aaa.Pbdata)[i]);
    end;
    Result := s;
  end;

begin
  FIssuedBy := GetDecodedName(CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);
  FIssuedTo := GetDecodedName(CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);
  FValidFrom := ConvertFileTimeToDateTime(FCertContext^.pCertInfo.NotBefore);
  FValidTo := ConvertFileTimeToDateTime(FCertContext^.pCertInfo.NotAfter);
  fIssuerName := getIssuerName;
  FSerialNumber := GetBLOBToBin(FCertContext^.pCertInfo.SerialNumber);
  fSignatureAlgorithm := FCertContext^.pCertInfo.SignatureAlgorithm.pszObjId^;
  fIssuerUniqueId := GetBinToHex(FCertContext^.pCertInfo.IssuerUniqueId);
  fSubjectUniqueId := GetBinToHex(FCertContext^.pCertInfo.SubjectUniqueId);
  FFriendlyName := GetFriendlyName(CERT_FRIENDLY_NAME_PROP_ID);
  FSHA1 := GetFriendlyName(CERT_SHA1_HASH_PROP_ID);
  getCertEncode;
end;

function tCertificateWin.getIssuerName;
var
  nameBLOB:   CERT_NAME_BLOB;
  encType:    DWORD;
  nameString: PChar;
  fSize:      integer;

begin
  nameString := StrAlloc(512);
  encType := PKCS_7_ASN_ENCODING or X509_ASN_ENCODING;
  nameBLOB := fCertContext^.pCertInfo^.Issuer;
  fsize := CertNameToStr(encType, @nameBlob,
    CERT_X500_NAME_STR + CERT_NAME_STR_REVERSE_FLAG, nameString, 512);
  if fSize > 0 then
    Result := nameString
  else
    Result := '';
  strDispose(nameString);
end;


function tCertificateWin.aquireContext;
var
  keySpec:    DWORD;
  callerFree: BOOL;

begin
  if (not CryptAcquireCertificatePrivateKey(Context, CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
    nil, Result, @keySpec, @callerFree)) or (not callerFree) then
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
  dwPropId: longword;
begin
  Result := '';
  dwPropID := CertEnumCertificateContextProperties(fCertContext, 0);
  while dwPropid <> 0 do
  begin
    case dwPropId of
      CERT_SHA1_HASH_PROP_ID: Result := Result + 'SHA1_HASH_PROP|';
      CERT_KEY_IDENTIFIER_PROP_ID: Result := Result + 'KEY_IDENTIFIER_PROP|';
      CERT_KEY_CONTEXT_PROP_ID: Result := Result + 'KEY CONTEXT PROP|'
      else
        Result := Result + IntToStr(dwPropId) + '|';
    end;


    dwPropID := CertEnumCertificateContextProperties(fCertContext, dwPropID);
  end;
end;


class function TCertificateWin.GetLastErrorText(const AFuncName: string): string;
var
  code:   DWORD;
  Len:    integer;
  Buffer: array[0..255] of char;
begin
  // WinHttpCertCfg.exe, a Certificate Configuration Tool
  //  http://msdn.microsoft.com/en-us/library/windows/desktop/aa384088%28v=vs.85%29.aspx
  code := GetLastError();
  Len := FormatMessage(FORMAT_MESSAGE_FROM_HMODULE or FORMAT_MESSAGE_FROM_SYSTEM,
    Pointer(GetModuleHandle('crypt32.dll')), code, 0, Buffer, SizeOf(Buffer), nil);
  while (Len > 0) and (Buffer[Len - 1] in [#0..#32, '.']) do
    Dec(Len);
  SetString(Result, Buffer, Len);
  if (Trim(Result) = '') then
  begin
    Result := Format('%s error - %d', [AFuncName, code]);
  end
  else
    Result := Result + '  module:' + AFuncName + '   error:' + inttohex(code, 8);
end;

function TCertificateWin.GetAvailableProviderType: cardinal;
var
  i, len: cardinal;
begin
  i := 0;
  while CryptEnumProviderTypes(i, nil, 0, Result, nil, len) do
  begin
    if (Result in [PROV_RSA_FULL, PROV_DSS, PROV_RSA_SCHANNEL,
      PROV_DSS_DH, PROV_DH_SCHANNEL, PROV_RSA_AES]) then
      Exit;
    Inc(i);
  end;
  Result := PROV_RSA_FULL;
end;


function TCertificateWin.GetSignatureValue(const AXml: string): string;
var
  xProv:   HCRYPTPROV;
  hash:    HCRYPTHASH;
  sigData: TMemoryStream;
  sigSize, keySpec: DWORD;
  callerFree: BOOL;
begin
  if (not CryptAcquireCertificatePrivateKey(Context, CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
    nil, xProv, @keySpec, @callerFree)) or (not callerFree) then
  begin
    raise ECertificateError.Create(GetLastErrorText(
      'CryptAcquireCertificatePrivateKey'));
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
      Result := reversedString(Result);
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
