//
// pure-Delphi minimal exclusive c14n implementation (no comments)
//

// Revised XmlCanon.pas - Exclusive C14N implementation (no comments)
// Behaviour:
//     Implements Exclusive XML Canonicalization with tightened namespace emission:
//     - For each element, collect prefixes used inside its subtree.
//     - For each such prefix, emit a namespace declaration on the element only if:
//       * it is declared locally with a value different from the same prefix declared on an ancestor,
//       OR
//       * it is not declared on any ancestor (so subtree standalone needs it),
//       OR
//       * it is listed among inclusive namespaces.
// In other words, if an ancestor already declares the same prefix->URI mapping, the current
// element will NOT redeclare it (to avoid redundant declarations), per the user's request.

unit XmlCanon;

interface

uses
  SysUtils,
  Classes,
  Types,
  Generics.Collections,
  Generics.Defaults,
  MSXML;

// Canonicalize a DOM node (element or documentElement) using exclusive c14n (no comments)
// Returns UTF-8 bytes of canonicalized node
function ExclusiveC14NToBytes(const Node: IXMLDOMNode): TBytes;

implementation

uses
  StrUtils,
  Variants;

function IfThen(const Cond: Boolean; const TrueValue: String; const FalseValue: String = ''): String; inline;
begin
  if Cond then
    Result := TrueValue
  else
    Result := FalseValue;
end;

{$IF CompilerVersion < 33.0}
type
  TDictionary<TKey, TValue> = class(Generics.Collections.TDictionary<TKey, TValue>)
  public
    class function TryAdd(ADict: TDictionary<TKey, TValue>; const AKey: TKey; const AValue: TValue): Boolean;
  end;

class function TDictionary<TKey, TValue>.TryAdd(ADict: TDictionary<TKey, TValue>; const AKey: TKey; const AValue: TValue): Boolean;
begin
  if ADict.ContainsKey(AKey) then
    Exit(False);

  ADict.Add(AKey, AValue);
  Result := True;
end;
{$ENDIF}

function EscapeText(const S: String): String;
begin
  Result := S;
  Result := StringReplace(Result, '&', '&amp;', [rfReplaceAll]);
  Result := StringReplace(Result, '<', '&lt;', [rfReplaceAll]);
  Result := StringReplace(Result, '>', '&gt;', [rfReplaceAll]);
  Result := StringReplace(Result, #13, '&#xD;', [rfReplaceAll]);
end;

function EscapeAttr(const S: String): String;
begin
  Result := S;
  Result := StringReplace(Result, '&', '&amp;', [rfReplaceAll]);
  Result := StringReplace(Result, '<', '&lt;', [rfReplaceAll]);
  Result := StringReplace(Result, '"', '&quot;', [rfReplaceAll]);
  Result := StringReplace(Result, #13, '&#xD;', [rfReplaceAll]);
  Result := StringReplace(Result, #10, '&#xA;', [rfReplaceAll]);
  Result := StringReplace(Result, #9, '&#x9;', [rfReplaceAll]);
end;

// Helper to collect namespace declarations declared on this element only
procedure CollectElementNamespaces(elem: IXMLDOMElement; out NsList: TDictionary<String, String>);
var
  attrs: IXMLDOMNamedNodeMap;
  i: Integer;
  attr: IXMLDOMAttribute;
  name, prefix: String;
begin
  NsList := TDictionary<String, String>.Create;
  attrs := elem.attributes as IXMLDOMNamedNodeMap;
  if attrs = Nil then
    Exit;

  for i := 0 to attrs.length - 1 do begin
    attr := attrs.item[i] as IXMLDOMAttribute;
    if attr = Nil then
      Continue;
    name := attr.nodeName;
    if StartsText('xmlns:', name) then begin
      prefix := Copy(name, 7, MaxInt);
      if not NsList.ContainsKey(prefix) then
        NsList.Add(prefix, VarToStr(attr.nodeValue));
    end
    else if name = 'xmlns' then begin
      if not NsList.ContainsKey('') then
        NsList.Add('', VarToStr(attr.nodeValue));
    end;
  end;
end;

// Build a map of in-scope namespaces from ancestors (closest ancestor wins)
function BuildAncestorInScopeNamespaces(startNode: IXMLDOMNode): TDictionary<String, String>;
var
  cur: IXMLDOMNode;
  attrs: IXMLDOMNamedNodeMap;
  i: Integer;
  attr: IXMLDOMAttribute;
  name, prefix: String;
begin
  Result := TDictionary<String, String>.Create;
  cur := startNode.parentNode;
  while Assigned(cur) do begin
    if cur.nodeType = NODE_ELEMENT then begin
      attrs := (cur as IXMLDOMElement).attributes as IXMLDOMNamedNodeMap;
      if attrs <> Nil then begin
        for i := 0 to attrs.length - 1 do begin
          attr := attrs.item[i] as IXMLDOMAttribute;
          if attr = Nil then
            Continue;
          name := attr.nodeName;
          if StartsText('xmlns:', name) then begin
            prefix := Copy(name, 7, MaxInt);
            if not Result.ContainsKey(prefix) then
              Result.Add(prefix, VarToStr(attr.nodeValue));
          end
          else if name = 'xmlns' then begin
            if not Result.ContainsKey('') then
              Result.Add('', VarToStr(attr.nodeValue));
          end;
        end;
      end;
    end;
    cur := cur.parentNode;
  end;
end;

// Walk subtree and collect prefixes that are actually used (elements' prefixes and attributes' prefixes)
// For elements with no prefix but with namespaceURI, we record the default prefix key ''.
procedure CollectUsedPrefixesInSubtree(root: IXMLDOMNode; out UsedPrefixes: TDictionary<String, Boolean>);
var
  stack: TList<IXMLDOMNode>;
  node: IXMLDOMNode;
  attrs: IXMLDOMNamedNodeMap;
  i: Integer;
  attr: IXMLDOMNode;
  pref, ns: String;
  e: IXMLDOMElement;
begin
  UsedPrefixes := TDictionary<String, Boolean>.Create;
  stack := TList<IXMLDOMNode>.Create;
  try
    stack.Add(root);
    while stack.Count > 0 do begin
      node := stack[stack.Count - 1];
      stack.Delete(stack.Count - 1);

      if node.nodeType = NODE_ELEMENT then begin
        e := node as IXMLDOMElement;
        pref := VarToStr(e.prefix);
        ns := VarToStr(e.namespaceURI);
        if pref <> '' then
        {$IF CompilerVersion < 33.0}
          TDictionary<String, Boolean>.TryAdd(UsedPrefixes, pref, True)
        {$ELSE}
          UsedPrefixes.TryAdd(pref, True)
        {$ENDIF}
        else begin
          // element with no prefix but with namespaceURI -> default-namespace usage
          if (ns <> '') then
          {$IF CompilerVersion < 33.0}
            TDictionary<String, Boolean>.TryAdd(UsedPrefixes, '', True);
          {$ELSE}
            UsedPrefixes.TryAdd('', True);
          {$ENDIF}
        end;

        // attributes
        attrs := e.attributes as IXMLDOMNamedNodeMap;
        if attrs <> Nil then begin
          for i := 0 to attrs.length - 1 do begin
            attr := attrs.item[i];
            if attr = Nil then
              Continue;
            // skip namespace declarations
            if (CompareText(attr.nodeName, 'xmlns') = 0) or StartsText('xmlns:', attr.nodeName) then
              Continue;
            pref := VarToStr((attr as IXMLDOMAttribute).prefix);
            if pref <> '' then
            {$IF CompilerVersion < 33.0}
              TDictionary<String, Boolean>.TryAdd(UsedPrefixes, pref, True);
            {$ELSE}
              UsedPrefixes.TryAdd(pref, True);
            {$ENDIF}
          end;
        end;
      end;

      // push children
      if Assigned(node.childNodes) then begin
        for i := 0 to node.childNodes.length - 1 do
          stack.Add(node.childNodes.item[i]);
      end;
    end;
  finally
    stack.Free;
  end;
end;

// Sort attributes lexicographically by namespace URI then local name
function SortedAttributes(elem: IXMLDOMElement): TArray<IXMLDOMAttribute>;
var
  attrs: IXMLDOMNamedNodeMap;
  i: Integer;
  list: TList<IXMLDOMAttribute>;
  attr: IXMLDOMAttribute;
begin
  list := TList<IXMLDOMAttribute>.Create;
  try
    attrs := elem.attributes as IXMLDOMNamedNodeMap;
    if attrs <> Nil then begin
      for i := 0 to attrs.length - 1 do begin
        attr := attrs.item[i] as IXMLDOMAttribute;
        if attr = Nil then
          Continue;
        // skip namespace declarations for now (emit separately)
        if StartsText('xmlns:', attr.nodeName) or (attr.nodeName = 'xmlns') then
          Continue;
        list.Add(attr);
      end;
    end;
    // sort by namespaceURI then baseName (case-insensitive)
    list.Sort(TComparer<IXMLDOMAttribute>.Construct(
      function(const L, R: IXMLDOMAttribute): Integer
      begin
        Result := CompareText(VarToStr(L.namespaceURI), VarToStr(R.namespaceURI));
        if Result = 0 then
          Result := CompareText(L.baseName, R.baseName);
      end)
    );
    Result := list.ToArray;
  finally
    list.Free;
  end;
end;

// Walk ancestors to resolve a needed prefix -> returns first encounter of declaration
function ResolvePrefixInAncestors(startNode: IXMLDOMNode; const prefix: String): String;
var
  cur: IXMLDOMNode;
  attrs: IXMLDOMNamedNodeMap;
  i: Integer;
  attr: IXMLDOMAttribute;
  name: String;
begin
  Result := '';
  cur := startNode.parentNode;
  while Assigned(cur) do begin
    if cur.nodeType = NODE_ELEMENT then begin
      attrs := (cur as IXMLDOMElement).attributes as IXMLDOMNamedNodeMap;
      if attrs <> Nil then begin
        for i := 0 to attrs.length - 1 do begin
          attr := attrs.item[i] as IXMLDOMAttribute;
          if attr = Nil then
            Continue;
          name := attr.nodeName;
          if (prefix = '') then begin
            if name = 'xmlns' then begin
              Result := VarToStr(attr.nodeValue);
              Exit;
            end;
          end
          else begin
            if StartsText('xmlns:', name) and SameText(Copy(name, 7, MaxInt), prefix) then begin
              Result := VarToStr(attr.nodeValue);
              Exit;
            end;
          end;
        end;
      end;
    end;
    cur := cur.parentNode;
  end;
end;

function IsInclusivePrefix(const Prefixes: TArray<String>; const P: String): Boolean;
var
  i: Integer;
begin
  for i := 0 to Length(Prefixes)-1 do
    if SameText(Prefixes[i], P) then
      Exit(True);
  Result := False;
end;

// Serialize node recursively with tightened visibility rules
procedure SerializeNode(node: IXMLDOMNode; sb: TStringBuilder; inclusiveNamespaces: TArray<String>);
var
  elem: IXMLDOMElement;
  attrs: TArray<IXMLDOMAttribute>;
  declared, ancestorNs: TDictionary<String, String>;
  usedPrefixes: TDictionary<String, Boolean>;
  keys: TArray<String>;
  i: Integer;
  prefix, nsuri: String;
  child: IXMLDOMNode;
  attr: IXMLDOMAttribute;
  resolved: TDictionary<String, String>;
  prefixList: TList<String>;
begin
  case node.nodeType of
    NODE_ELEMENT: begin
      elem := node as IXMLDOMElement;

      // start tag
      sb.Append('<');
      if elem.prefix <> '' then
        sb.Append(elem.prefix).Append(':').Append(elem.baseName)
      else
        sb.Append(elem.baseName);

      // prepare sorted attributes
      attrs := SortedAttributes(elem);

      // declared namespaces ON this element
      CollectElementNamespaces(elem, declared);
      try
        // collect prefixes used by subtree to decide which ancestor ns we need
        CollectUsedPrefixesInSubtree(node, usedPrefixes);
        try
          // build ancestor in-scope namespaces (closest ancestor wins)
          ancestorNs := BuildAncestorInScopeNamespaces(elem);
          try
            resolved := TDictionary<String, String>.Create;
            try
              // 1) Consider local declarations first: include them only if they are needed
              for prefix in declared.Keys do begin
                if (usedPrefixes.ContainsKey(prefix) or IsInclusivePrefix(inclusiveNamespaces, prefix)) then begin
                  // if ancestor declares same prefix with identical URI, skip (redundant)
                  if ancestorNs.ContainsKey(prefix) and (ancestorNs.Items[prefix] = declared.Items[prefix]) then
                    Continue;
                  resolved.Add(prefix, declared.Items[prefix]);
                end;
              end;

              // 2) Now consider used prefixes that are not covered by local declarations
              for prefix in usedPrefixes.Keys do begin
                if resolved.ContainsKey(prefix) then
                  Continue;
                // if ancestor already has it declared (same mapping), then skip per user's requirement
                if ancestorNs.ContainsKey(prefix) then
                  Continue;

                // try to resolve from ancestors (this will return '' if not found)
                nsuri := ResolvePrefixInAncestors(elem, prefix);
                if (nsuri <> '') or IsInclusivePrefix(inclusiveNamespaces, prefix) then begin
                  resolved.Add(prefix, nsuri);
                end;
              end;

              // Emit namespace declarations from resolved in stable order: default ('') first, then sorted prefixes
              if resolved.ContainsKey('') then
                sb.Append(' xmlns="').Append(EscapeAttr(resolved.Items[''])).Append('"');

              keys := resolved.Keys.ToArray;
              prefixList := TList<String>.Create;
              try
                for i := 0 to Length(keys)-1 do
                  if keys[i] <> '' then
                    prefixList.Add(keys[i]);
                prefixList.Sort;
                for i := 0 to prefixList.Count-1 do
                  sb.Append(' xmlns:').Append(prefixList[i]).Append('="').Append(EscapeAttr(resolved.Items[prefixList[i]])).Append('"');
              finally
                prefixList.Free;
              end;
            finally
              resolved.Free;
            end;
          finally
            ancestorNs.Free;
          end;
        finally
          usedPrefixes.Free;
        end;
      finally
        declared.Free;
      end;

      // emit attributes (already sorted)
      for i := 0 to Length(attrs)-1 do begin
        attr := attrs[i];
        if attr = Nil then
          Continue;
        if attr.prefix <> '' then
          sb.Append(' ').Append(attr.prefix).Append(':').Append(attr.baseName)
        else
          sb.Append(' ').Append(attr.baseName);

        sb.Append('="').Append(EscapeAttr(VarToStr(attr.nodeValue))).Append('"');
      end;

//      if not elem.hasChildNodes then
//        sb.Append('/');
      sb.Append('>');

      // children
      if elem.hasChildNodes then begin
        child := elem.firstChild;
        while Assigned(child) do begin
          SerializeNode(child, sb, inclusiveNamespaces);
          child := child.nextSibling;
        end;
      end;

//        // end tag
//        sb.Append('</');
//        if elem.prefix <> '' then
//          sb.Append(elem.prefix).Append(':').Append(elem.baseName)
//        else
//          sb.Append(elem.baseName);
//        sb.Append('>');
//      end;

      // end tag
      sb.Append('</');
      if elem.prefix <> '' then
        sb.Append(elem.prefix).Append(':').Append(elem.baseName)
      else
        sb.Append(elem.baseName);
      sb.Append('>');
    end;
    NODE_TEXT: begin
      sb.Append(EscapeText(VarToStr(node.nodeValue)));
    end;
    NODE_CDATA_SECTION: begin
      // treat CDATA as text nodes
      sb.Append(EscapeText(VarToStr(node.nodeValue)));
    end;
    NODE_COMMENT: ; // skip comments for exc-c14n without comments
    NODE_DOCUMENT: begin
      if Assigned((node as IXMLDOMDocument).documentElement) then
        SerializeNode((node as IXMLDOMDocument).documentElement, sb, inclusiveNamespaces);
    end;
  end;
end;

function ExclusiveC14NToBytes(const Node: IXMLDOMNode): TBytes;
var
  sb: TStringBuilder;
  s: String;
begin
  sb := TStringBuilder.Create;
  try
    SerializeNode(Node, sb, []);
    s := sb.ToString;
    Result := TEncoding.UTF8.GetBytes(s);
  finally
    sb.Free;
  end;
end;

end.
