'use strict';
// AI USE-CASE INVENTORY 2026-10-20. Reads the InfoSec / Legal "AI/ML Use Inventory" workbook
// and fills the stored copy of it for export. zlib only (the hub has no spreadsheet library).
// Reading is bounded (entry count, inflate size per part and in total), refuses ZIP64,
// encrypted and multi-disk files, and never evaluates formulas: the three calculated
// columns are recomputed from the record (ai-governance-use-case-model.js calc()).
const zlib=require('node:zlib');
const model=require('./ai-governance-use-case-model');
// F12: parts are capped at 20 MB inflated (the real template's largest part is ~0.6 MB), and every
// regex that reads uploaded XML stops at the next tag ([^<>], or a tempered run that ends at the
// next opening tag of the same name), so an unclosed tag costs linear time, not quadratic.
const LIMITS={entries:2000,partBytes:20*1024*1024,totalBytes:40*1024*1024};
const FIRST_DATA_ROW=6,TEMPLATE_LAST_ROW=505,WIDTH=model.COLUMNS.length;
function bad(message){throw Object.assign(new Error(message),{status:400});}

// ── zip ───────────────────────────────────────────────────────────────
const CRC=new Int32Array(256).map((_,n)=>{let c=n;for(let k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;return c;});
function crc32(b){let c=-1;for(let i=0;i<b.length;i++)c=CRC[(c^b[i])&255]^(c>>>8);return (c^-1)>>>0;}
function readZip(buf){
  if(!Buffer.isBuffer(buf)||buf.length<22)bad('The file is not an .xlsx workbook');
  let eocd=-1;
  for(let i=buf.length-22;i>=Math.max(0,buf.length-22-65535);i--)if(buf.readUInt32LE(i)===0x06054b50){eocd=i;break;}
  if(eocd<0)bad('The file is not an .xlsx workbook');
  if(buf.readUInt16LE(eocd+4)||buf.readUInt16LE(eocd+6))bad('Multi-part archives are not supported');
  const count=buf.readUInt16LE(eocd+10),size=buf.readUInt32LE(eocd+12),offset=buf.readUInt32LE(eocd+16);
  if(count===0xFFFF||size===0xFFFFFFFF||offset===0xFFFFFFFF)bad('ZIP64 workbooks are not supported');
  if(count>LIMITS.entries)bad('The workbook has too many parts');
  if(offset+size>eocd)bad('The workbook is damaged');
  const entries=new Map();let p=offset;
  for(let n=0;n<count;n++){
    if(p+46>eocd||buf.readUInt32LE(p)!==0x02014b50)bad('The workbook is damaged');
    const e={flags:buf.readUInt16LE(p+8),method:buf.readUInt16LE(p+10),crc:buf.readUInt32LE(p+16),csize:buf.readUInt32LE(p+20),usize:buf.readUInt32LE(p+24),local:buf.readUInt32LE(p+42)};
    const nlen=buf.readUInt16LE(p+28),xlen=buf.readUInt16LE(p+30),clen=buf.readUInt16LE(p+32);
    e.name=buf.toString('utf8',p+46,p+46+nlen);p+=46+nlen+xlen+clen;
    if(e.flags&1)bad('Password-protected or encrypted workbooks are not supported');
    if(e.csize===0xFFFFFFFF||e.usize===0xFFFFFFFF||e.local===0xFFFFFFFF)bad('ZIP64 workbooks are not supported');
    entries.set(e.name,e);
  }
  return entries;
}
function inflate(buf,e,budget){
  if(e.usize>LIMITS.partBytes)bad('A workbook part is too large');
  const p=e.local;
  if(p+30>buf.length||buf.readUInt32LE(p)!==0x04034b50)bad('The workbook is damaged');
  const start=p+30+buf.readUInt16LE(p+26)+buf.readUInt16LE(p+28);
  if(start+e.csize>buf.length)bad('The workbook is damaged');
  const raw=buf.subarray(start,start+e.csize);let out;
  if(e.method===0)out=raw;
  else if(e.method===8){try{out=zlib.inflateRawSync(raw,{maxOutputLength:LIMITS.partBytes});}catch(err){bad(err&&err.code==='ERR_BUFFER_TOO_LARGE'?'A workbook part is too large':'The workbook is damaged');}}
  else bad('The workbook uses an unsupported compression method');
  if(out.length!==e.usize||crc32(out)!==e.crc)bad('The workbook is damaged');
  budget.used+=out.length;if(budget.used>LIMITS.totalBytes)bad('The workbook is too large');
  return out;
}
function writeZip(files){
  const parts=[],central=[];let offset=0;
  for(const f of files){
    const name=Buffer.from(f.name,'utf8'),data=zlib.deflateRawSync(f.data),crc=crc32(f.data);
    const h=Buffer.alloc(30),c=Buffer.alloc(46);
    // Fixed DOS date 1980-01-01 00:00, UTF-8 names (flag 0x0800), deflate.
    h.writeUInt32LE(0x04034b50,0);h.writeUInt16LE(20,4);h.writeUInt16LE(0x0800,6);h.writeUInt16LE(8,8);h.writeUInt16LE(0,10);h.writeUInt16LE(0x21,12);
    h.writeUInt32LE(crc,14);h.writeUInt32LE(data.length,18);h.writeUInt32LE(f.data.length,22);h.writeUInt16LE(name.length,26);h.writeUInt16LE(0,28);
    c.writeUInt32LE(0x02014b50,0);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(0x0800,8);c.writeUInt16LE(8,10);c.writeUInt16LE(0,12);c.writeUInt16LE(0x21,14);
    c.writeUInt32LE(crc,16);c.writeUInt32LE(data.length,20);c.writeUInt32LE(f.data.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE(offset,42);
    parts.push(h,name,data);central.push(c,name);offset+=30+name.length+data.length;
  }
  const cd=Buffer.concat(central),end=Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(files.length,8);end.writeUInt16LE(files.length,10);end.writeUInt32LE(cd.length,12);end.writeUInt32LE(offset,16);
  return Buffer.concat([...parts,cd,end]);
}

// ── xml ───────────────────────────────────────────────────────────────
const ENT={amp:'&',lt:'<',gt:'>',quot:'"',apos:"'"};
function unxml(s){return String(s).replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g,(m,e)=>{if(e[0]!=='#')return ENT[e];const n=e[1]==='x'?parseInt(e.slice(2),16):Number(e.slice(1));return n>0&&n<=0x10FFFF?String.fromCodePoint(n):'';});}
const unescapeX=s=>s.replace(/_x([0-9A-Fa-f]{4})_/g,(m,h)=>String.fromCharCode(parseInt(h,16)));
function attrs(s){s=String(s);const a={},gone={};const re=/(?<![\w:.-])([\w:.-]+)\s*=\s*(["'])/g;let m;
  while((m=re.exec(s))){const q=m[2],end=gone[q]?-1:s.indexOf(q,re.lastIndex);if(end<0){gone[q]=true;continue;}a[m[1]]=unxml(s.slice(re.lastIndex,end));re.lastIndex=end+1;}
  return a;}
// Rich-text runs are joined; phonetic (rPh) runs are not cell text.
function text(xml){return unescapeX([...String(xml).replace(/<(?:\w+:)?rPh\b(?:(?!<(?:\w+:)?rPh\b)[\s\S])*?<\/(?:\w+:)?rPh>/g,'').matchAll(/<(?:\w+:)?t(?:\s[^<>]*)?>((?:(?!<(?:\w+:)?t[\s>])[\s\S])*?)<\/(?:\w+:)?t>/g)].map(m=>unxml(m[1])).join(''));}
function rels(xml,base){return [...String(xml||'').matchAll(/<(?:\w+:)?Relationship\b([^<>]*?)\/?>/g)].map(m=>attrs(m[1])).map(a=>({id:a.Id,type:a.Type||'',target:a.TargetMode==='External'?null:resolve(base,a.Target||'')}));}
function resolve(base,target){const out=[];for(const p of (target.startsWith('/')?target.slice(1):base+target).split('/')){if(p==='..')out.pop();else if(p&&p!=='.')out.push(p);}return out.join('/');}
const squash=v=>String(v).replace(/\s+/g,' ').trim();
function colIndex(letters){let n=0;for(const ch of letters)n=n*26+ch.charCodeAt(0)-64;return n-1;}
function esc(s){return String(s).replace(/\r\n?/g,'\n').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g,'').replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g,'')
  .replace(/_x([0-9A-Fa-f]{4})_/g,'_x005F_x$1_').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

// Finds the workbook, its relationships, shared strings and a named sheet.
function open(buf){
  const entries=readZip(buf),budget={used:0},cache=new Map();
  const get=name=>{if(!cache.has(name)){const e=entries.get(name);cache.set(name,e?inflate(buf,e,budget).toString('utf8'):null);}return cache.get(name);};
  const root=rels(get('_rels/.rels'),'').find(r=>/\/officeDocument$/.test(r.type));
  const wbPath=root&&root.target||'xl/workbook.xml',wb=get(wbPath);
  if(!wb)bad('The file is not an .xlsx workbook');
  const base=wbPath.replace(/[^/]*$/,''),relsPath=base+'_rels/'+wbPath.slice(base.length)+'.rels',wbRels=rels(get(relsPath),base);
  const sheets=[...wb.matchAll(/<(?:\w+:)?sheet\b([^<>]*?)\/?>/g)].map(m=>attrs(m[1])).map(a=>{const rid=Object.keys(a).find(k=>/:id$/.test(k));const r=wbRels.find(x=>x.id===a[rid]);return {name:a.name||'',path:r&&r.target};});
  const sheet=name=>sheets.find(s=>squash(s.name).toLowerCase()===name.toLowerCase());
  return {entries,get,wb,wbPath,relsPath,wbRels,sheet,date1904:/<(?:\w+:)?workbookPr\b[^<>]*\bdate1904\s*=\s*["'](?:1|true)["']/.test(wb)};
}

// ── read ──────────────────────────────────────────────────────────────
function serialDate(n,date1904){
  let d=Math.floor(n);if(!Number.isFinite(d)||d<1)return null;
  if(date1904)d+=1462;else if(d===60)return null;else if(d<60)d+=1;   // Excel's 1900-02-29
  const t=new Date(Date.UTC(1899,11,30)+d*86400000);const y=t.getUTCFullYear();
  return y>=1900&&y<=9999?t.toISOString().slice(0,10):null;
}
function looseDate(s){
  let m=/^(\d{4}-\d{2}-\d{2})(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?$/.exec(s);if(m)return m[1];
  m=/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(s);if(m)return m[3]+'-'+m[1].padStart(2,'0')+'-'+m[2].padStart(2,'0');
  return s;
}
const num=s=>{const n=Number(s);return Number.isFinite(n)?String(Number(n.toPrecision(15))):s;};
function cellValue(a,inner,strings){
  const t=a.t||'n';inner=inner||'';
  if(t==='inlineStr'){const m=/<(?:\w+:)?is\b[^<>]*>((?:(?!<(?:\w+:)?is\b)[\s\S])*?)<\/(?:\w+:)?is>/.exec(inner);return {v:m?text(m[1]):''};}
  const m=/<(?:\w+:)?v(?:\s[^<>]*)?>((?:(?!<(?:\w+:)?v[\s>])[\s\S])*?)<\/(?:\w+:)?v>/.exec(inner),raw=m?unxml(m[1]):'';
  if(t==='s'){if(raw==='')return {v:''};const s=strings[Number(raw)];if(s==null)bad('The workbook is damaged (missing shared text)');return {v:s};}
  if(t==='str')return {v:unescapeX(raw)};
  if(t==='b')return {v:raw==='1'?'TRUE':raw==='0'?'FALSE':raw};
  if(t==='e')return {v:'',error:raw||'#ERROR'};
  if(t==='d')return {v:raw,iso:true};
  return {v:raw,number:raw!==''};
}
// -> {rows:[{row,id,values,problems}], skipped:[{row,reason}]}. Header row 4 must be the
// template's; row 5 (the example) is ignored; data starts at row 6.
function parseInventory(buf,{maxRows=2000}={}){
  const book=open(buf),inv=book.sheet('Inventory');
  if(!inv||!inv.path)bad('The workbook has no "Inventory" sheet. Use the AI/ML Use Inventory template.');
  const xml=book.get(inv.path);if(xml==null)bad('The workbook is damaged (Inventory sheet missing)');
  const ss=book.wbRels.find(r=>/\/sharedStrings$/.test(r.type));
  const strings=ss&&ss.target&&book.get(ss.target)?[...book.get(ss.target).matchAll(/<(?:\w+:)?si\b[^<>]*?(?:\/>|>((?:(?!<(?:\w+:)?si\b)[\s\S])*?)<\/(?:\w+:)?si>)/g)].map(m=>m[1]?text(m[1]):''):[];
  const grid=new Map();let rowNo=0,filled=0;
  for(const m of xml.matchAll(/<(?:\w+:)?row\b([^<>]*?)(?:\/>|>((?:(?!<(?:\w+:)?row\b)[\s\S])*?)<\/(?:\w+:)?row>)/g)){
    const a=attrs(m[1]);rowNo=a.r?Number(a.r):rowNo+1;
    if(!Number.isSafeInteger(rowNo)||rowNo<1||rowNo>1048576)bad('The workbook is damaged (row number)');
    const cells=new Map();let col=-1;
    for(const c of (m[2]||'').matchAll(/<(?:\w+:)?c\b([^<>]*?)(?:\/>|>((?:(?!<(?:\w+:)?c\b)[\s\S])*?)<\/(?:\w+:)?c>)/g)){
      const ca=attrs(c[1]);
      if(ca.r){const x=/^\$?([A-Z]{1,3})\$?(\d+)$/.exec(ca.r.toUpperCase());if(!x)bad('The workbook is damaged (cell reference)');col=colIndex(x[1]);}else col++;
      if(col<WIDTH)cells.set(col,cellValue(ca,c[2],strings));
    }
    if(rowNo>=FIRST_DATA_ROW&&model.COLUMNS.some((k,i)=>!k.calculated&&String(cells.get(i)?.v||'').trim()!==''||cells.get(i)?.error&&!k.calculated)&&++filled>maxRows)
      bad('The workbook has more than '+maxRows+' filled rows');
    grid.set(rowNo,cells);
  }
  const head=grid.get(4)||new Map(),norm=v=>squash(String(v||'').replace(/\*/g,'')).toLowerCase();
  const wrong=model.HEADERS.map((h,i)=>({col:model.COLUMNS[i].col,want:h,got:squash(head.get(i)?.v||'')})).filter(x=>norm(x.want)!==norm(x.got));
  if(wrong.length)bad('This is not the AI/ML Use Inventory template: row 4 '+wrong.slice(0,3).map(x=>'column '+x.col+' should be "'+x.want+'" but is "'+x.got.slice(0,60)+'"').join('; ')+(wrong.length>3?' (and '+(wrong.length-3)+' more)':''));
  const rows=[],skipped=[];
  for(const n of [...grid.keys()].filter(n=>n>=FIRST_DATA_ROW).sort((a,b)=>a-b)){
    const cells=grid.get(n),values={},problems=[];let any=false;
    model.COLUMNS.forEach((k,i)=>{
      if(k.calculated||k.key==='id')return;
      const c=cells.get(i);if(!c)return;
      if(c.error){problems.push(k.label+' (column '+k.col+') has a spreadsheet error '+c.error);any=true;return;}
      let v=squash(c.v)===''?'':String(c.v).replace(/\r\n?/g,'\n').trim();
      if(v&&k.field.kind==='date')v=c.number?serialDate(Number(v),book.date1904)||v:c.iso?v.slice(0,10):looseDate(v);
      else if(v&&c.number)v=num(v);
      if(v){values[k.key]=v;any=true;}
    });
    const id=squash(cells.get(0)?.v||'');
    if(!any){if(id)skipped.push({row:n,reason:'Only an ID ('+id.slice(0,30)+'); no use-case data'});continue;}
    if(!values.name){skipped.push({row:n,reason:'No name in column C'});continue;}
    rows.push({row:n,id,values,problems});
  }
  return {sheet:inv.name,rows,skipped};
}

// ── export ────────────────────────────────────────────────────────────
function isoSerial(day){const [y,m,d]=day.split('-').map(Number);return Math.round((Date.UTC(y,m-1,d)-Date.UTC(1899,11,30))/86400000);}
function cell(ref,s,{text:t,number,f}={}){
  const sa=s!=null?' s="'+s+'"':'',fx=f||'';
  if(number!=null)return '<c r="'+ref+'"'+sa+'>'+fx+'<v>'+number+'</v></c>';
  if(fx)return '<c r="'+ref+'"'+sa+' t="str">'+fx+'<v>'+esc(t||'')+'</v></c>';
  if(t)return '<c r="'+ref+'"'+sa+' t="inlineStr"><is><t xml:space="preserve">'+esc(t)+'</t></is></c>';
  return '<c r="'+ref+'"'+sa+'/>';
}
// One record -> the 45 cells of row n. styles: column index -> style id; formulas: column
// index -> the <f> element to keep (template rows) or to write (rows past the template).
function rowCells(n,rec,styles,formulas){
  return model.COLUMNS.map((k,i)=>{
    const ref=k.col+n,s=styles.get(i),f=formulas.get(i);
    if(k.key==='id')return cell(ref,s,{text:rec.ref});
    if(k.calculated){const v=rec.calc[k.key];
      if(k.key==='required_blank')return v===''?cell(ref,s,{f,text:''}):cell(ref,s,{f,number:v});
      if(k.key==='next_review'&&model.validDate(v))return cell(ref,s,{f,number:isoSerial(v)});
      return cell(ref,s,{f,text:v});}
    const v=rec.profile[k.key]||'';
    if(v&&k.field.kind==='date'&&model.validDate(v))return cell(ref,s,{number:isoSerial(v)});
    return cell(ref,s,{text:v});
  }).join('');
}
// Summary-sheet formulas are COUNTA / COUNTIF sums over Inventory columns; their cached
// values are recomputed here so viewers that do not recalculate show real counts.
function summaryValue(formula,records){
  const terms=[...unxml(formula).matchAll(/([+-]?)\s*(COUNTA|COUNTIF)\(Inventory!\$([A-Z]{1,3})\$6:\$\3\$\d+(?:,"([^"]*)")?\)/g)];
  if(!terms.length||terms.map(t=>t[0]).join('').replace(/\s/g,'')!==unxml(formula).replace(/\s/g,''))return null;
  let total=0;
  for(const [,sign,fn,col,crit] of terms){
    const k=model.COLUMNS.find(c=>c.col===col);if(!k||(fn==='COUNTA')!==(crit==null))return null;
    const vals=records.map(r=>k.key==='id'?r.ref:k.calculated?r.calc[k.key]:r.profile[k.key]||'');
    let n;
    if(fn==='COUNTA'){if(k.calculated)return null;n=vals.filter(v=>v!=='').length;}
    else if(/^>\d+$/.test(crit))n=vals.filter(v=>typeof v==='number'&&v>Number(crit.slice(1))).length;
    else n=vals.filter(v=>String(v).toLowerCase()===crit.toLowerCase()).length;
    total+=sign==='-'?-n:n;
  }
  return total;
}
// records: [{ref, profile, calc}] in output order. Returns the filled workbook.
// opts.evidence (AI USE-CASE ENRICHMENT 2026-10-20): adds column AT, "Source / evidence
// reference (CorpIT)", after the template's last column. The importer reads columns A..AS
// only, so an exported workbook still imports.
const EVIDENCE_COL='AT',EVIDENCE_HEADER='Source / evidence reference (CorpIT)';
function buildExport(template,records,now=new Date(),opts={}){
  const book=open(template),inv=book.sheet('Inventory'),sum=book.sheet('Summary');
  if(!inv||!inv.path)throw new Error('use-case template has no Inventory sheet');
  const last=Math.max(TEMPLATE_LAST_ROW,FIRST_DATA_ROW-1+records.length),out=new Map();
  let xml=book.get(inv.path);
  const master=new Map(),rowXml=new Map();
  for(const m of xml.matchAll(/<row r="(\d+)"([^>]*)>([\s\S]*?)<\/row>/g))if(m[1]==='5'||m[1]===String(TEMPLATE_LAST_ROW))rowXml.set(m[1],m);
  for(const c of rowXml.get('5')[3].matchAll(/<c r="([A-Z]+)5"[^>]*>(<f\b[^>]*>([\s\S]*?)<\/f>)/g))master.set(colIndex(c[1]),c[3]);
  const evidenceCell=(n,rec,styles)=>opts.evidence&&rec?cell(EVIDENCE_COL+n,styles.get(WIDTH-1),{text:rec.evidence||''}):'';
  const parse=inner=>{const styles=new Map(),formulas=new Map();for(const c of inner.matchAll(/<c r="([A-Z]+)\d+"([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)){const i=colIndex(c[1]),s=/\bs="(\d+)"/.exec(c[2]),f=/<f\b[^>]*\/>|<f\b[^>]*>[\s\S]*?<\/f>/.exec(c[3]||'');if(s)styles.set(i,s[1]);if(f)formulas.set(i,f[0]);}return {styles,formulas};};
  xml=xml.replace(/<row r="(\d+)"([^>]*)>([\s\S]*?)<\/row>/g,(m,r,a,inner)=>{
    const n=Number(r),rec=records[n-FIRST_DATA_ROW];if(n<FIRST_DATA_ROW||!rec)return m;
    const {styles,formulas}=parse(inner);return '<row r="'+n+'"'+a+'>'+rowCells(n,rec,styles,formulas)+evidenceCell(n,rec,styles)+'</row>';
  });
  if(last>TEMPLATE_LAST_ROW){
    // Rows past the template: row 505's styles, explicit formulas from the row-5 masters.
    const t=rowXml.get(String(TEMPLATE_LAST_ROW)),{styles}=parse(t[3]),extra=[];
    for(let n=TEMPLATE_LAST_ROW+1;n<=last;n++){
      const formulas=new Map([...master].map(([i,f])=>[i,'<f>'+f.replace(/(?<![A-Za-z0-9_$.])(\$?[A-Z]{1,3})5(?![0-9])/g,(x,c)=>c+n)+'</f>']));
      extra.push('<row r="'+n+'"'+t[2]+'>'+rowCells(n,records[n-FIRST_DATA_ROW],styles,formulas)+evidenceCell(n,records[n-FIRST_DATA_ROW],styles)+'</row>');
    }
    xml=xml.replace('</sheetData>',extra.join('')+'</sheetData>');
    const grow=s=>s.replace(/([A-Z]{1,3})5:([A-Z]{1,3})505(?![0-9])/g,(x,a,b)=>a+'5:'+b+last);
    xml=xml.replace(/sqref="([^"]*)"/g,(m,v)=>'sqref="'+grow(v)+'"');
  }
  xml=xml.replace(/(<dimension ref="A1:[A-Z]+)\d+"/,'$1'+last+'"').replace(/(<autoFilter ref="A4:[A-Z]+)\d+"/,'$1'+last+'"').replace(/(<pane\b[^>]*\btopLeftCell=")[A-Z]+\d+"/,'$1D5"');
  if(opts.evidence){
    xml=xml.replace(/(<row r="4"[^>]*>[\s\S]*?)<\/row>/,(m,body)=>{const s=/<c r="[A-Z]+4"[^>]*\bs="(\d+)"/.exec(body);return body+cell(EVIDENCE_COL+'4',s&&s[1],{text:EVIDENCE_HEADER})+'</row>';})
      .replace('</cols>','<col min="'+(WIDTH+1)+'" max="'+(WIDTH+1)+'" width="60" customWidth="1"/></cols>')
      .replace(/ spans="1:45"/g,' spans="1:'+(WIDTH+1)+'"').replace(/(<dimension ref="A1:)[A-Z]+(\d+")/,'$1'+EVIDENCE_COL+'$2');
  }
  out.set(inv.path,xml);
  if(sum&&sum.path){
    out.set(sum.path,book.get(sum.path).replace(/<c r="([A-Z]+\d+)"([^>]*)><f>([^<]*)<\/f>(?:<v>[^<]*<\/v>|<v\/>)?<\/c>/g,(m,ref,a,f)=>{
      const formula=last>TEMPLATE_LAST_ROW?f.replace(/\$505(?![0-9])/g,'$'+last):f,v=summaryValue(formula,records);
      return '<c r="'+ref+'"'+a.replace(/\st="[^"]*"/,'')+'><f>'+formula+'</f>'+(v==null?'':'<v>'+v+'</v>')+'</c>';
    }));
  }
  // Excel rebuilds the calculation chain and recalculates on open.
  out.set(book.wbPath,book.wb.replace(/<calcPr\b([^>]*?)\/>/,(m,a)=>/fullCalcOnLoad/.test(a)?m:'<calcPr'+a+' fullCalcOnLoad="1"/>').replace(/(Inventory!\$A\$4:\$[A-Z]+\$)\d+/,'$1'+last));
  const chain=book.wbRels.find(r=>/\/calcChain$/.test(r.type));
  if(chain){
    out.set(book.relsPath,book.get(book.relsPath).replace(/<Relationship\b[^>]*\/calcChain"[^>]*\/>/,''));
    out.set('[Content_Types].xml',book.get('[Content_Types].xml').replace(/<Override PartName="\/?xl\/calcChain\.xml"[^>]*\/>/,''));
  }
  const core=book.get('docProps/core.xml');
  if(core)out.set('docProps/core.xml',core.replace(/<cp:lastModifiedBy>[\s\S]*?<\/cp:lastModifiedBy>/,'<cp:lastModifiedBy>CorpIT AI Governance export</cp:lastModifiedBy>')
    .replace(/(<dcterms:modified\b[^>]*>)[^<]*/,'$1'+now.toISOString().replace(/\.\d+Z$/,'Z')));
  const files=[];
  for(const e of book.entries.values()){
    if(chain&&e.name===chain.target)continue;
    files.push({name:e.name,data:out.has(e.name)?Buffer.from(out.get(e.name),'utf8'):inflate(template,e,{used:0})});
  }
  return writeZip(files);
}
module.exports={parseInventory,buildExport,readZip,crc32,LIMITS};
