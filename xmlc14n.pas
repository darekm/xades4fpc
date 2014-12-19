{****************************************************************************
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

{ changelog
}


unit xmlc14n;

{$H+}

interface

uses
  dom,
  SysUtils,
  Classes;

type
  TXCanonicalizer = class
  private
    nsStack: TStringList;
    function BuildXmlString(ANode: TDOMNode): utf8String;
    function BuildAttributes(ANode: TDOMNode): utf8String;
    function BuildPI(ANode: TDOMNode): utf8String;
    function NormalizeAttributeValue(AValue: utf8String): utf8String;
    function NormalizeText(AText: utf8String): utf8String;
    function nodeIsNS(aNode: tDomNode): boolean;
    function NSStackFind(aName: string): boolean;
  protected
    procedure init;
    procedure done;
  public
    function Canonicalize(ARootNode: TDOMNode): utf8string; overload;
    function Canonicalize(ADoc: TXMLDocument): utf8string; overload;
  end;

implementation


function utf8StringReplace(const S, OldPattern, NewPattern: utf8String): utf8String;
var
  SearchStr, Patt, NewStr: WideString;
  Offset: integer;
begin
  SearchStr := S;
  Patt := OldPattern;

  NewStr := S;
  Result := '';
  while (SearchStr <> '') do
  begin
    Offset := system.Pos(Patt, SearchStr);
    if Offset = 0 then
    begin
      Result := Result + NewStr;
      Break;
    end;
    Result := Result + system.Copy(NewStr, 1, Offset - 1) + NewPattern;
    NewStr := system.Copy(NewStr, Offset + Length(OldPattern), MaxInt);
    SearchStr := system.Copy(SearchStr, Offset + Length(Patt), MaxInt);
  end;
end;


function TXCanonicalizer.NormalizeAttributeValue(AValue: utf8String): utf8String;
begin
  Result := AValue;
  Result := utf8StringReplace(Result, '"', '&quot;');
  Result := utf8StringReplace(Result, '&', '&amp;');
  Result := utf8StringReplace(Result, #9, #32);
  Result := utf8StringReplace(Result, #13#10, #32);
  Result := utf8StringReplace(Result, #13, #32);
  Result := utf8StringReplace(Result, #10, #32);
end;

function TXCanonicalizer.NormalizeText(AText: utf8String): utf8String;
begin
  Result := AText;
  Result := utf8StringReplace(Result, #13#10, #10);
  Result := utf8StringReplace(Result, #13, #10);
end;

function tXCanonicalizer.BuildPI(Anode: TDOMNode): utf8String;
begin
  Result := '<!' + TDOMProcessingInstruction(Anode).Target +
    ' ' + TDOMProcessingInstruction(Anode).Data + '>'#10;
end;

function tXCanonicalizer.nodeIsNS(aNode: tDomNode): boolean;
begin
  Result := (system.Pos('xmlns', LowerCase(aNode.nodeName)) = 1);
end;

function tXCanonicalizer.nsStackFind(aName: string): boolean;
var
  i: integer;
begin
  Result := nsStack.Find(aName, i);
  if not Result then
    nsStack.add(aName);
end;



function TXCanonicalizer.BuildAttributes(ANode: TDOMNode): utf8String;
var
  i: integer;
  attributes, namespaces: TStringList;
  element: TDOMElement;
  xNSName: string;

  procedure parseNS(aNode: tDomNode);
  var
    i: integer;
    xNSName: string;
  begin
    if aNode.Attributes = nil then
      exit;
    for i := 0 to aNode.attributes.length - 1 do
    begin
      if nodeIsNS(aNode.attributes.item[i]) then
      begin
        xNSName := aNode.attributes.item[i].nodeName +
          '="' + NormalizeAttributeValue(aNode.attributes.item[i].nodeValue) + '"';
        if not NsStackFind(xNSName) then
          namespaces.Add(xNSName);
      end;
    end;
  end;

begin
  Result := '';
  if aNode.nodeType <> Element_node then
    Exit;

  attributes := nil;
  namespaces := nil;
  try
    attributes := TStringList.Create();
    attributes.Sorted := True;

    namespaces := TStringList.Create();
    namespaces.Sorted := True;

    element := (ANode as TDOMElement);
    while (element.ParentNode <> nil) and (element.parentNode is tDomElement) do
    begin
      element := element.parentNode as tDomElement;
      parseNS(element);
    end;
    element := (ANode as TDOMElement);

    for i := 0 to element.attributes.length - 1 do
    begin
      xNSName := element.attributes.item[i].nodeName +
        '="' + NormalizeAttributeValue(element.attributes.item[i].nodeValue) + '"';
      if nodeIsNS(element.attributes.item[i]) then
      begin
        if not NsStackFind(xNSName) then
          namespaces.Add(xNSName);
      end
      else
      begin
        attributes.Add(xNSName);
      end;
    end;
    for i := 0 to namespaces.Count - 1 do
    begin
      Result := Result + ' ' + Trim(namespaces[i]);
    end;
    for i := 0 to attributes.Count - 1 do
    begin
      Result := Result + ' ' + Trim(attributes[i]);
    end;
  finally
    namespaces.Free();
    attributes.Free();
  end;
end;

function TXCanonicalizer.BuildXmlString(ANode: TDOMNode): utf8String;
var
  i: integer;
begin
  case anode.NodeType of
    TEXT_NODE: Result := Result + NormalizeText(ANode.nodeValue);
    CDATA_SECTION_NODE: ;
    COMMENT_NODE: ;
    PROCESSING_INSTRUCTION_NODE: Result := Result + BuildPi(ANode);
    else
    begin
      Result := #10'<' + ANode.nodeName + BuildAttributes(ANode) + '>';
      for i := 0 to ANode.childNodes.Count - 1 do
      begin
        Result := Result + BuildXmlString(ANode.childNodes.item[i]);
      end;
      Result := Result + '</' + ANode.nodeName + '>'#10;
    end;
  end;
end;

procedure TXCanonicalizer.Init;
begin
  nsStack := TStringList.Create;
end;

procedure TXCanonicalizer.done;
begin
  nsStack.Free;
end;

function TXCanonicalizer.Canonicalize(ARootNode: TDOMNode): utf8string;
begin
  init;
  Result := BuildXmlString(ArootNode);
  if (Result <> '') and (Result[length(Result)] = #10) then
    Delete(Result, length(Result), 1);
  if (Result <> '') and (Result[1] = #10) then
    Delete(Result, 1, 1);
  done;
end;

function TXCanonicalizer.Canonicalize(ADoc: TXMLDocument): utf8string;
var
  Child: TDOMNode;
begin
  init;
  Result := '';
  if Length(adoc.StylesheetType) > 0 then
  begin
    Result := Result + '<?xml-stylesheet type="';
    //    ConvWrite(aDoc.StylesheetType, AttrSpecialChars, @AttrSpecialCharCallback);
    Result := Result + '" href="';
    //    ConvWrite(aDoc.StylesheetHRef, AttrSpecialChars, @AttrSpecialCharCallback);
    Result := Result + '"?>';
  end;
  Result := Result + buildXmlString(Child);
  if (Result <> '') and (Result[length(Result)] = #10) then
    Delete(Result, length(Result), 1);
  done;
end;



end.
