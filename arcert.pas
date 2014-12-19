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




unit arcert;
{$H+}
interface

uses
  Classes,
  SysUtils;


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
    fIssuerUniqueID: string;
    fSubjectUniqueID: string;
    fSignatureAlgorithm: string;
    FFriendlyName: string;
    fSHA1: string;
    f509Data: string;
    f509Digest: string;
    function getSerialNumberDec: string;
    function getSerialNumberHex: string;

  public
    storePos: integer;
    property IssuedTo: string read FIssuedTo;
    property IssuedBy: string read FIssuedBy;
    property FriendlyName: string read FFriendlyName;
    property Email: string read FEmail;
    property ValidFrom: TDateTime read FValidFrom;
    property ValidTo: TDateTime read FValidTo;
    property SerialNumberHex: string read getSerialNumberHex;
    property SerialNumberDec: string read getSerialNumberDec;
    property XSHA1: string read FSHA1;
    property signatureAlgorith: string read fSignatureAlgorithm;
    property IssuerUniqueID: string read fIssuerUniqueId;
    property issuerName: string read fIssuerName;
    property X509Data: string read f509Data;

    function GetSignatureValue(const AXml: string): string; virtual;
    function GetDigestValue(const AXml: string): string; virtual;
    property x509Digest: string read f509Digest;
    function all: string;
    function title: string;
    function toXml: utf8String;
  end;


type
  ECertificateError = class(Exception);

implementation

uses
  flxml,      // private unit used to presentation
  wpdate,
  wpstring;

const

  CRYPT_E_NOT_FOUND = ($80092004);//2148081668
  CRYPT_E_SELF_SIGNED = ($80092007);


function tCertificate.all: string;
begin
  Result := 'issuedBy:' + fIssuedBy + #10;
  Result := Result + 'issuedTo:' + fIssuedTo + #10;
  Result := Result + 'issuerName:' + fIssuerName + #10;
  Result := Result + 'serialnumber:' + fSerialNumber + #10;
  Result := Result + 'subjectunique:' + fSubjectUniqueID + #10;
  Result := Result + 'friendlyName:' + fFriendlyName + #10;
  Result := Result + 'sha1:' + fsha1;
end;

function tCertificate.title;
begin
  Result := pad(issuerName, 33) + ' ' + pad(issuedto, 28) + date4st(ValidTo) + ' ' + serialNumberHex;
end;

function tCertificate.getSerialNumberDec: string;
begin
  Result := BinToDec(fSerialNumber);
end;

function tCertificate.getSerialNumberHex: string;
begin
  Result := BinToHEX(fSerialNumber);
end;

function tCertificate.GetSignatureValue(const AXml: string): string;
begin
  Result := '';
end;

function tCertificate.GetDigestValue(const AXml: string): string;
begin
  Result := '';
end;

function tCertificate.toXml;
begin
  Result := px('SerialNumber', serialNumberHex) + px(
    'IssuerName', IssuerName) + px('X509Data', x509Data) +
    px('ValidTo', dbl2int64(ValidTo)) + px('ValidFrom', dbl2int64(ValidFrom));
end;


end.
