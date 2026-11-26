"""Independent offline ACME checks; JWS signatures are verified locally."""
import base64,concurrent.futures,json,threading,unittest
import josepy as jose
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from acme import client,errors,jws,messages

KEY=jose.JWKRSA(key=rsa.generate_private_key(public_exponent=65537,key_size=2048))
NONCE='https://ca.example.invalid/acme/nonce';ORDER='https://ca.example.invalid/acme/order'
def enc(value):return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
def response(url,status=200,nonce=None,problem=False):
 r=requests.Response();r.status_code=status;r.url=url;r.history=[];r.headers['Content-Type']='application/problem+json' if problem else 'application/json'
 r._content=json.dumps({'type':'urn:ietf:params:acme:error:badNonce','detail':'local fixture'} if problem else {}).encode()
 if nonce is not None:r.headers['Replay-Nonce']=nonce
 return r
class Session:
 def __init__(self,handler):self.handler=handler;self.posts=[];self.lock=threading.Lock()
 def request(self,method,url,**kwargs):
  parsed=None
  if method=='POST':
   signed=jws.JWS.json_loads(kwargs['data']);assert signed.verify(KEY.public_key())
   parsed=(signed.signature.combined.nonce,signed.payload)
   with self.lock:self.posts.append(parsed)
  return self.handler(method,url,parsed)
 def close(self):pass
 def mount(self,*a):pass
class Payload(jose.JSONDeSerializable):
 def __init__(self):self.calls=0
 def json_dumps(self,**kwargs):self.calls+=1;return json.dumps({'calls':self.calls})
 def to_partial_json(self):return {}
 @classmethod
 def from_json(cls,obj):return cls()
def network(handler,manager=None):
 n=client.ClientNetwork(KEY,account={'uri':'https://ca.example.invalid/account/1'},nonce_manager=manager,max_bad_nonce_retries=1)
 n.session=Session(handler);return n

class Contract(unittest.TestCase):
 def test_single_badnonce_preserves_one_serialization(self):
  count=[0]
  def handler(method,url,data):
   if method=='HEAD':return response(url,nonce=enc(b'initial'))
   count[0]+=1
   return response(url,400,enc(b'fresh'),True) if count[0]==1 else response(url,nonce=enc(b'after'))
  n=network(handler);obj=Payload();n.post(ORDER,obj,new_nonce_url=NONCE)
  self.assertEqual(obj.calls,1);self.assertEqual(n.session.posts[0][1],n.session.posts[1][1]);self.assertEqual(n.session.posts[1][0],b'fresh')
 def test_post_as_get_has_empty_payload(self):
  n=network(lambda method,url,data:response(url,nonce=enc(b'initial' if method=='HEAD' else b'after')))
  n.post(ORDER,None,new_nonce_url=NONCE);self.assertEqual(n.session.posts[0][1],b'')
 def test_transport_error_is_not_retried(self):
  def handler(method,url,data):
   if method=='HEAD':return response(url,nonce=enc(b'initial'))
   raise requests.ConnectionError('synthetic transport failure')
  n=network(handler)
  with self.assertRaises(requests.ConnectionError):n.post(ORDER,Payload(),new_nonce_url=NONCE)
  self.assertEqual(len(n.session.posts),1)
 def test_pool_capacity_expiry_and_atomic_claim(self):
  clock=[10.];m=client.NonceManager(max_size=2,max_age=5,clock=lambda:clock[0]);s=m.scope_for(NONCE,'one')
  for x in [b'a',b'b',b'c']:m.add_nonce(s,enc(x))
  self.assertEqual(m.available_count(s),2)
  with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:r=list(pool.map(lambda _:m.claim_nonce(s),range(4)))
  self.assertEqual(len([x for x in r if x is not None]),2);self.assertEqual(len(set(x for x in r if x is not None)),2)
  m.add_nonce(s,enc(b'd'));clock[0]=15.;self.assertIsNone(m.claim_nonce(s))
 def test_scopes_do_not_mix_same_nonce_bytes(self):
  m=client.NonceManager();a=m.scope_for(NONCE,'a');b=m.scope_for(NONCE+'-other','a');m.add_nonce(a,enc(b'x'));m.add_nonce(b,enc(b'x'))
  self.assertEqual(m.claim_nonce(a),b'x');self.assertEqual(m.claim_nonce(b),b'x')
 def test_badnonce_duplicate_cannot_be_claimed_by_two_requests(self):
  gate=threading.Barrier(2);m=client.NonceManager();initials=iter([b'first-a',b'first-b']);lock=threading.Lock()
  def make():
   count=[0]
   def handler(method,url,data):
    if method=='HEAD':
     with lock:value=next(initials)
     return response(url,nonce=enc(value))
    count[0]+=1
    if count[0]==1:gate.wait(timeout=10);return response(url,400,enc(b'same-error-nonce'),True)
    return response(url,nonce=enc(b'after-'+data[0]))
   return network(handler,m)
  a,b=make(),make()
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   fs=[pool.submit(n.post,ORDER,Payload(),new_nonce_url=NONCE) for n in (a,b)]
   for f in fs:
    try:f.result(timeout=15)
    except (errors.Error,StopIteration):pass
  used=[nonce for n in [a,b] for nonce,payload in n.session.posts if nonce==b'same-error-nonce']
  self.assertLessEqual(len(used),1,'same error-response nonce was signed into two requests')
 def test_base64url_padding_is_rejected(self):
  m=client.NonceManager();s=m.scope_for(NONCE,'a')
  with self.assertRaises(Exception):m.add_nonce(s,'UQ==')

if __name__=='__main__':unittest.main(verbosity=2)
