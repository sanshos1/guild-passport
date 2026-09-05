# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import hashlib,json
def c(v,n=900):return str(v).strip()[:n]
def kid(v):
 x=c(v,72).upper()
 if not x:raise gl.vm.UserError('[EXPECTED] passport id required')
 return x
def url(v):
 s=c(v,500);r=s[8:] if s.startswith('https://') else '';h=r.split('/')[0].lower();p=r[len(h):]
 if not h or '.' not in h or '@' in h or not p.startswith('/'):raise gl.vm.UserError('[EXPECTED] valid HTTPS source')
 return s,h
def obj(v):
 if isinstance(v,dict):return v
 s=str(v);a=s.find('{');b=s.rfind('}')
 if a<0 or b<=a:raise gl.vm.UserError('[LLM_ERROR] invalid JSON')
 return json.loads(s[a:b+1])
@allow_storage
@dataclass
class Passport:issuer:str;subject:str;kind:str;sources:str;state:str;claims:str;digests:str
class GuildPassport(gl.Contract):
 admin:Address;issuers:TreeMap[str,bool];passports:TreeMap[str,Passport]
 def __init__(self):self.admin=gl.message.sender_address
 @gl.public.write
 def authorize_issuer(self,issuer:str,allowed:bool)->None:
  if gl.message.sender_address!=self.admin:raise gl.vm.UserError('[EXPECTED] admin only')
  self.issuers[c(issuer,42).lower()]=allowed
 def _get(self,i):
  k=kid(i)
  if k not in self.passports:raise gl.vm.UserError('[EXPECTED] passport not found')
  return k,self.passports[k]
 @gl.public.write
 def draft(self,i:str,subject:str,kind:str,sources:list[str])->None:
  k=kid(i)
  issuer=gl.message.sender_address.as_hex.lower()
  if k in self.passports or not self.issuers.get(issuer,False):raise gl.vm.UserError('[EXPECTED] authorized unique issuer required')
  p=[url(x) for x in sources]
  if len(p)!=2 or p[0][1]==p[1][1]:raise gl.vm.UserError('[EXPECTED] two independent source hosts required')
  self.passports[k]=Passport(issuer,c(subject,42).lower(),c(kind,100),json.dumps([x[0] for x in p]),'DRAFT','[]','[]')
 @gl.public.write
 def consent(self,i:str)->None:
  _,p=self._get(i)
  if p.subject!=gl.message.sender_address.as_hex.lower() or p.state!='DRAFT':raise gl.vm.UserError('[EXPECTED] subject draft required')
  p.state='CONSENTED'
 def _verify(self,p):
  urls=json.loads(p.sources)
  def run():
   docs=[];dig=[]
   for ix,u in enumerate(urls):
    raw=gl.nondet.web.get(u).body[:12000];b=raw if isinstance(raw,bytes) else str(raw).encode();dig.append(hashlib.sha256(b).hexdigest());docs.append({'slot':ix,'body':b.decode(errors='replace')})
   q='Verify that registry slot 0 authorizes the issuer and credential slot 1 identifies the subject and credential kind. JSON only {"valid":true,"claim_codes":[]}. KIND:'+p.kind+' ISSUER:'+p.issuer+' SUBJECT:'+p.subject+' DOCS:'+json.dumps(docs)
   x=obj(gl.nondet.exec_prompt(q,response_format='json'));return {'valid':bool(x.get('valid',False)),'claims':sorted(set(c(x,80).upper() for x in x.get('claim_codes',[])[:20] if c(x,80))),'digests':dig}
  def valid(x):
   if not isinstance(x,gl.vm.Return):return False
   try:
    g=x.calldata;docs=[];dig=[]
    for ix,u in enumerate(urls):
     raw=gl.nondet.web.get(u).body[:12000];b=raw if isinstance(raw,bytes) else str(raw).encode();dig.append(hashlib.sha256(b).hexdigest());docs.append({'slot':ix,'body':b.decode(errors='replace')})
    if g['digests']!=dig:return False
    q='Independently verify exact validity and claim codes. JSON only {"valid":true}. PROPOSAL:'+json.dumps(g)+' DOCS:'+json.dumps(docs)
    return bool(obj(gl.nondet.exec_prompt(q,response_format='json')).get('valid',False))
   except:return False
  return gl.vm.run_nondet_unsafe(run,valid)
 @gl.public.write
 def activate(self,i:str)->None:
  _,p=self._get(i)
  if p.state!='CONSENTED':raise gl.vm.UserError('[EXPECTED] consent required')
  x=self._verify(p);p.digests=json.dumps(x['digests']);p.claims=json.dumps(x['claims']);p.state='ACTIVE' if x['valid'] else 'REJECTED'
 @gl.public.write
 def revoke(self,i:str)->None:
  _,p=self._get(i)
  if p.issuer!=gl.message.sender_address.as_hex.lower() or p.state!='ACTIVE':raise gl.vm.UserError('[EXPECTED] issuer active passport required')
  p.state='REVOKED'
 @gl.public.view
 def get_passport(self,i:str)->dict:
  k,p=self._get(i);return {'id':k,'issuer':p.issuer,'subject':p.subject,'kind':p.kind,'sources':json.loads(p.sources),'state':p.state,'claimCodes':json.loads(p.claims),'digests':json.loads(p.digests)}
