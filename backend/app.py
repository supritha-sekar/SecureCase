"""Secure Digital Document Management System: local educational implementation."""
import os, io, json, hmac, hashlib, secrets, uuid, mimetypes, zipfile
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import or_
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from reportlab.pdfgen import canvas
from pypdf import PdfReader, PdfWriter
from PIL import Image

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / '.env')
DB = SQLAlchemy()
PH = PasswordHasher()
limiter = Limiter(key_func=lambda: str(session.get('uid') or get_remote_address()), default_limits=['300 per hour'], storage_uri='memory://')
ROLES = ('administrator', 'investigator', 'legal_advisor', 'clerk')
ALLOWED = {'.pdf','.docx','.jpg','.png','.mp4','.txt'}
MAX_FILE = 25 * 1024 * 1024

def now(): return datetime.now(timezone.utc)
def iso(v): return v.isoformat() if v else None

class User(DB.Model):
 id=DB.Column(DB.Integer,primary_key=True)
 username=DB.Column(DB.String(80),unique=True,nullable=False)
 password_hash=DB.Column(DB.Text,nullable=False)
 role=DB.Column(DB.String(30),nullable=False,default='clerk')
 active=DB.Column(DB.Boolean,default=True,nullable=False)
 failed=DB.Column(DB.Integer,default=0,nullable=False)
 locked_until=DB.Column(DB.DateTime(timezone=True))
 def view(self): return dict(id=self.id,username=self.username,role=self.role,active=self.active)

class Case(DB.Model):
 id=DB.Column(DB.Integer,primary_key=True)
 number=DB.Column(DB.String(80),unique=True,nullable=False)
 title=DB.Column(DB.String(200),nullable=False)
 description=DB.Column(DB.Text,default='')
 status=DB.Column(DB.String(20),default='Open')
 created_by=DB.Column(DB.Integer,DB.ForeignKey('user.id'))
 created_at=DB.Column(DB.DateTime(timezone=True),default=now)
 def view(self): return dict(id=self.id,number=self.number,title=self.title,description=self.description,status=self.status,created_at=iso(self.created_at),members=[x.user_id for x in Assignment.query.filter_by(case_id=self.id).all()])

class Assignment(DB.Model):
 id=DB.Column(DB.Integer,primary_key=True)
 case_id=DB.Column(DB.Integer,DB.ForeignKey('case.id'),nullable=False)
 user_id=DB.Column(DB.Integer,DB.ForeignKey('user.id'),nullable=False)
 __table_args__=(DB.UniqueConstraint('case_id','user_id'),)

class Document(DB.Model):
 id=DB.Column(DB.Integer,primary_key=True)
 case_id=DB.Column(DB.Integer,DB.ForeignKey('case.id'),nullable=False)
 name=DB.Column(DB.String(255),nullable=False)
 doc_type=DB.Column(DB.String(80),default='Other')
 uploaded_by=DB.Column(DB.Integer,DB.ForeignKey('user.id'))
 created_at=DB.Column(DB.DateTime(timezone=True),default=now)
 def view(self):
  versions=Version.query.filter_by(document_id=self.id).order_by(Version.number.desc()).all()
  return dict(id=self.id,case_id=self.case_id,name=self.name,doc_type=self.doc_type,uploaded_by=self.uploaded_by,created_at=iso(self.created_at),versions=[v.view() for v in versions],current_version=versions[0].number if versions else 0)

class Version(DB.Model):
 id=DB.Column(DB.Integer,primary_key=True)
 document_id=DB.Column(DB.Integer,DB.ForeignKey('document.id'),nullable=False)
 number=DB.Column(DB.Integer,nullable=False)
 sha256=DB.Column(DB.String(64),nullable=False)
 nonce=DB.Column(DB.LargeBinary(12),nullable=False)
 path=DB.Column(DB.String(100),nullable=False)
 size=DB.Column(DB.Integer,nullable=False)
 uploaded_by=DB.Column(DB.Integer,DB.ForeignKey('user.id'))
 created_at=DB.Column(DB.DateTime(timezone=True),default=now)
 __table_args__=(DB.UniqueConstraint('document_id','number'),)
 def view(self): return dict(id=self.id,number=self.number,sha256=self.sha256,size=self.size,uploaded_by=self.uploaded_by,created_at=iso(self.created_at))

class Share(DB.Model):
 id=DB.Column(DB.Integer,primary_key=True)
 document_id=DB.Column(DB.Integer,DB.ForeignKey('document.id'),nullable=False)
 user_id=DB.Column(DB.Integer,DB.ForeignKey('user.id'),nullable=False)
 expires_at=DB.Column(DB.DateTime(timezone=True),nullable=False)
 created_by=DB.Column(DB.Integer,DB.ForeignKey('user.id'))

class Audit(DB.Model):
 id=DB.Column(DB.Integer,primary_key=True)
 timestamp=DB.Column(DB.String(50),nullable=False)
 user_id=DB.Column(DB.Integer)
 role=DB.Column(DB.String(30))
 action=DB.Column(DB.String(100),nullable=False)
 case_id=DB.Column(DB.Integer)
 document_id=DB.Column(DB.Integer)
 result=DB.Column(DB.String(30),nullable=False)
 previous_hash=DB.Column(DB.String(64),nullable=False)
 entry_hash=DB.Column(DB.String(64),nullable=False)
 def payload(self): return dict(timestamp=self.timestamp,user_id=self.user_id,role=self.role,action=self.action,case_id=self.case_id,document_id=self.document_id,result=self.result,previous_hash=self.previous_hash)
 def view(self): return dict(id=self.id,**self.payload(),entry_hash=self.entry_hash)

class Backup(DB.Model):
 id=DB.Column(DB.Integer,primary_key=True)
 filename=DB.Column(DB.String(255),nullable=False)
 created_at=DB.Column(DB.DateTime(timezone=True),default=now)
 created_by=DB.Column(DB.Integer,DB.ForeignKey('user.id'))

def canonical(payload): return json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def audit(action,result='success',case_id=None,document_id=None,user=None):
 u=user or current_user()
 prev=Audit.query.order_by(Audit.id.desc()).first()
 row=Audit(timestamp=iso(now()),user_id=u.id if u else None,role=u.role if u else None,action=action,case_id=case_id,document_id=document_id,result=result,previous_hash=prev.entry_hash if prev else '0'*64,entry_hash='')
 row.entry_hash=hashlib.sha256(canonical(row.payload())).hexdigest()
 DB.session.add(row)
 DB.session.commit()
 return row

def verify_audit():
 previous='0'*64
 for row in Audit.query.order_by(Audit.id).all():
  if row.previous_hash!=previous or not hmac.compare_digest(row.entry_hash,hashlib.sha256(canonical(row.payload())).hexdigest()):
   return dict(valid=False,broken_at=row.id)
  previous=row.entry_hash
 return dict(valid=True,entries=Audit.query.count(),head=previous)

def current_user():
 uid=session.get('uid')
 return DB.session.get(User,uid) if uid else None

def guard(fn):
 @wraps(fn)
 def wrapper(*a,**kw):
  u=current_user()
  if not u or not u.active: return jsonify(error='Authentication required'),401
  return fn(*a,**kw)
 return wrapper

def admin_only(fn):
 @wraps(fn)
 @guard
 def wrapper(*a,**kw):
  if current_user().role!='administrator': return jsonify(error='Administrator only'),403
  return fn(*a,**kw)
 return wrapper

def can_case(case_id):
 u=current_user()
 return bool(u and (u.role=='administrator' or Assignment.query.filter_by(case_id=case_id,user_id=u.id).first()))

def can_download(doc):
 u=current_user()
 if not u: return False
 if u.role=='administrator' or (u.role in ('investigator','legal_advisor') and can_case(doc.case_id)): return True
 share=Share.query.filter_by(document_id=doc.id,user_id=u.id).order_by(Share.id.desc()).first()
 return bool(share and share.expires_at.replace(tzinfo=timezone.utc)>now())

def ensure_case(case_id):
 c=DB.session.get(Case,case_id)
 if not c: abort(404)
 if not can_case(c.id):
  audit('case.access','denied',case_id=c.id)
  abort(403)
 return c

def ensure_doc(doc_id,download=False):
 d=DB.session.get(Document,doc_id)
 if not d: abort(404)
 if not (can_download(d) if download else can_case(d.case_id)):
  audit('document.access','denied',case_id=d.case_id,document_id=d.id)
  abort(403)
 return d

def validate_file(name,data):
 ext=Path(name).suffix.lower()
 if ext not in ALLOWED: raise ValueError('Unsupported extension')
 if not data or len(data)>MAX_FILE: raise ValueError('File must be between 1 byte and 25 MB')
 signatures={'.pdf':data.startswith(b'%PDF-'),'.png':data.startswith(b'\x89PNG\r\n\x1a\n'),'.jpg':data.startswith(b'\xff\xd8\xff'),'.docx':zipfile.is_zipfile(io.BytesIO(data)) and b'word/document.xml' in _zip_names(data),'.mp4':len(data)>12 and data[4:8]==b'ftyp','.txt':b'\x00' not in data}
 if not signatures[ext]: raise ValueError('File content does not match its extension')
 return ext

def _zip_names(data):
 try:
  with zipfile.ZipFile(io.BytesIO(data)) as z: return '\n'.join(z.namelist()).encode()
 except zipfile.BadZipFile: return b''

def save_version(doc,data):
 validate_file(doc.name,data)
 number=Version.query.filter_by(document_id=doc.id).count()+1
 nonce=os.urandom(12)
 ciphertext=AESGCM(bytes.fromhex(os.environ['DOCUMENT_KEY'])).encrypt(nonce,data,f'{doc.id}:{number}'.encode())
 filename=uuid.uuid4().hex+'.enc'
 store=Path(current_app_storage())
 (store/filename).write_bytes(ciphertext)
 v=Version(document_id=doc.id,number=number,nonce=nonce,path=filename,size=len(data),sha256=hashlib.sha256(data).hexdigest(),uploaded_by=current_user().id)
 DB.session.add(v);DB.session.commit()
 audit('document.version_uploaded',case_id=doc.case_id,document_id=doc.id)
 return v

def current_app_storage():
 from flask import current_app
 return current_app.config['STORAGE']

def read_version(doc,v):
 ciphertext=(Path(current_app_storage())/v.path).read_bytes()
 data=AESGCM(bytes.fromhex(os.environ['DOCUMENT_KEY'])).decrypt(v.nonce,ciphertext,f'{doc.id}:{v.number}'.encode())
 if not hmac.compare_digest(hashlib.sha256(data).hexdigest(),v.sha256): raise ValueError('Integrity verification failed')
 return data

def watermark(data,ext,username):
 stamp=f'Downloaded by {username} | {now().strftime("%Y-%m-%d %H:%M UTC")}'
 if ext=='.pdf':
  source=PdfReader(io.BytesIO(data));out=PdfWriter()
  for page in source.pages:
   buf=io.BytesIO(); c=canvas.Canvas(buf,pagesize=(float(page.mediabox.width),float(page.mediabox.height)))
   c.setFillGray(0.45);c.setFont('Helvetica',9);c.drawString(28,24,stamp);c.save();buf.seek(0)
   page.merge_page(PdfReader(buf).pages[0]);out.add_page(page)
  dest=io.BytesIO();out.write(dest);return dest.getvalue()
 if ext in ('.png','.jpg'):
  from PIL import ImageDraw
  img=Image.open(io.BytesIO(data)).convert('RGB');draw=ImageDraw.Draw(img)
  draw.rectangle((0,img.height-28,img.width,img.height),fill='white')
  draw.text((8,img.height-22),stamp,fill='black')
  dest=io.BytesIO();img.save(dest,format='PNG' if ext=='.png' else 'JPEG');return dest.getvalue()
 if ext=='.txt': return data+b'\n'+stamp.encode()+b'\n'
 # DOCX and MP4 are returned unchanged; see README limitation.
 return data

def create_app(test_config=None):
 app=Flask(__name__)
 app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY',''),SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL','sqlite:///sddms.db'),SQLALCHEMY_TRACK_MODIFICATIONS=False,MAX_CONTENT_LENGTH=MAX_FILE+1024*1024,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','false').lower()=='true',PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),STORAGE=str(BASE/'storage'))
 if test_config: app.config.update(test_config)
 if not app.config['SECRET_KEY'] or len(app.config['SECRET_KEY'])<32: raise RuntimeError('Set a strong SECRET_KEY in backend/.env')
 if not os.environ.get('DOCUMENT_KEY') or len(os.environ['DOCUMENT_KEY'])!=64: raise RuntimeError('Set DOCUMENT_KEY to 64 hex characters')
 bytes.fromhex(os.environ['DOCUMENT_KEY'])
 Path(app.config['STORAGE']).mkdir(parents=True,exist_ok=True)
 DB.init_app(app);limiter.init_app(app)

 @app.before_request
 def csrf_check():
  if request.method in ('POST','PUT','PATCH','DELETE') and request.endpoint not in ('login',):
   token=session.get('csrf')
   if not token or not hmac.compare_digest(str(request.headers.get('X-CSRF-Token','')),token):
    return jsonify(error='CSRF token missing or invalid'),403

 @app.errorhandler(403)
 @app.errorhandler(404)
 @app.errorhandler(413)
 def http_error(e): return jsonify(error=e.description),e.code

 @app.get('/api/csrf')
 def csrf():
  if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
  return jsonify(csrf=session['csrf'])

 @app.post('/api/login')
 @limiter.limit('8 per minute')
 def login():
  data=request.get_json(silent=True) or {}
  u=User.query.filter_by(username=str(data.get('username','')).strip()).first()
  locked=bool(u and u.locked_until and u.locked_until.replace(tzinfo=timezone.utc)>now())
  valid=False
  if u and not locked and u.active:
   try: valid=PH.verify(u.password_hash,str(data.get('password','')))
   except (VerifyMismatchError,VerificationError): pass
  if not valid:
   if u:
    u.failed+=1
    if u.failed>=5: u.locked_until=now()+timedelta(minutes=15);u.failed=0
    DB.session.commit()
   audit('auth.login','denied',user=u)
   return jsonify(error='Invalid credentials or account temporarily locked'),401
  u.failed=0;u.locked_until=None;DB.session.commit()
  session.clear();session['uid']=u.id;session['csrf']=secrets.token_urlsafe(32);session.permanent=True
  audit('auth.login',user=u)
  return jsonify(user=u.view(),csrf=session['csrf'])

 @app.post('/api/logout')
 @guard
 def logout():
  audit('auth.logout');session.clear();return jsonify(ok=True)

 @app.get('/api/me')
 @guard
 def me(): return jsonify(user=current_user().view())

 @app.get('/api/users')
 @admin_only
 def users(): return jsonify([u.view() for u in User.query.order_by(User.id).all()])

 @app.post('/api/users')
 @admin_only
 def create_user():
  data=request.get_json(silent=True) or {};name=str(data.get('username','')).strip();password=str(data.get('password',''));role=data.get('role')
  if not 3<=len(name)<=80 or len(password)<12 or role not in ROLES: return jsonify(error='Username 3-80 characters, password 12+ characters, valid role required'),400
  if User.query.filter_by(username=name).first(): return jsonify(error='Username exists'),409
  u=User(username=name,password_hash=PH.hash(password),role=role)
  DB.session.add(u);DB.session.commit();audit('user.created');return jsonify(u.view()),201

 @app.patch('/api/users/<int:uid>')
 @admin_only
 def update_user(uid):
  u=DB.session.get(User,uid)
  if not u: abort(404)
  data=request.get_json(silent=True) or {}
  if 'role' in data:
   if data['role'] not in ROLES: return jsonify(error='Invalid role'),400
   u.role=data['role']
  if 'active' in data:
   if u.id==current_user().id and not data['active']: return jsonify(error='Cannot deactivate self'),400
   u.active=bool(data['active'])
  DB.session.commit();audit('user.updated');return jsonify(u.view())

 @app.get('/api/cases')
 @guard
 def cases():
  u=current_user();q=Case.query
  if u.role!='administrator': q=q.join(Assignment,Assignment.case_id==Case.id).filter(Assignment.user_id==u.id)
  return jsonify([c.view() for c in q.order_by(Case.id.desc()).all()])

 @app.post('/api/cases')
 @guard
 def create_case():
  if current_user().role not in ('administrator','investigator'): return jsonify(error='Insufficient permission'),403
  data=request.get_json(silent=True) or {};title=str(data.get('title','')).strip();number=str(data.get('number','')).strip() or 'CASE-'+uuid.uuid4().hex[:8].upper()
  if not title or len(title)>200: return jsonify(error='Valid title required'),400
  if Case.query.filter_by(number=number).first(): return jsonify(error='Case number exists'),409
  c=Case(number=number,title=title,description=str(data.get('description',''))[:5000],created_by=current_user().id)
  DB.session.add(c);DB.session.flush();DB.session.add(Assignment(case_id=c.id,user_id=current_user().id));DB.session.commit();audit('case.created',case_id=c.id)
  return jsonify(c.view()),201

 @app.patch('/api/cases/<int:cid>')
 @guard
 def update_case(cid):
  c=ensure_case(cid)
  if current_user().role not in ('administrator','investigator'): abort(403)
  data=request.get_json(silent=True) or {}
  if 'status' in data:
   if data['status'] not in ('Open','Closed'): return jsonify(error='Invalid status'),400
   c.status=data['status']
  if 'title' in data and str(data['title']).strip(): c.title=str(data['title']).strip()[:200]
  DB.session.commit();audit('case.updated',case_id=cid);return jsonify(c.view())

 @app.post('/api/cases/<int:cid>/assign')
 @admin_only
 def assign(cid):
  c=DB.session.get(Case,cid)
  if not c: abort(404)
  uid=(request.get_json(silent=True) or {}).get('user_id')
  if not DB.session.get(User,uid): return jsonify(error='Unknown user'),404
  if not Assignment.query.filter_by(case_id=cid,user_id=uid).first(): DB.session.add(Assignment(case_id=cid,user_id=uid));DB.session.commit()
  audit('case.assigned',case_id=cid);return jsonify(c.view())

 @app.get('/api/documents')
 @guard
 def documents():
  cid=request.args.get('case_id',type=int);keyword=request.args.get('q','').strip()
  q=Document.query
  if current_user().role!='administrator':
   permitted=[a.case_id for a in Assignment.query.filter_by(user_id=current_user().id).all()]
   shared=[sh.document_id for sh in Share.query.filter_by(user_id=current_user().id).all() if sh.expires_at.replace(tzinfo=timezone.utc)>now()]
   q=q.filter(or_(Document.case_id.in_(permitted),Document.id.in_(shared)))
  if cid: q=q.filter(Document.case_id==cid)
  if keyword: q=q.join(Case,Document.case_id==Case.id).filter(or_(Document.name.ilike('%'+keyword+'%'),Document.doc_type.ilike('%'+keyword+'%'),Case.number.ilike('%'+keyword+'%')))
  return jsonify([d.view() for d in q.order_by(Document.id.desc()).all()])

 @app.post('/api/cases/<int:cid>/documents')
 @guard
 @limiter.limit('30 per hour')
 def upload(cid):
  ensure_case(cid)
  f=request.files.get('file')
  if not f: return jsonify(error='Select a file'),400
  name=secure_filename(f.filename or '')
  try: data=f.read();validate_file(name,data)
  except ValueError as e: return jsonify(error=str(e)),400
  d=Document(case_id=cid,name=name,doc_type=str(request.form.get('doc_type','Other'))[:80],uploaded_by=current_user().id)
  DB.session.add(d);DB.session.commit()
  try: save_version(d,data)
  except Exception: DB.session.delete(d);DB.session.commit();raise
  return jsonify(d.view()),201

 @app.get('/api/documents/<int:did>')
 @guard
 def document(did):
  d=ensure_doc(did,download=True);audit('document.view',case_id=d.case_id,document_id=d.id);return jsonify(d.view())

 @app.patch('/api/documents/<int:did>')
 @guard
 def document_meta(did):
  d=ensure_doc(did)
  data=request.get_json(silent=True) or {}
  if 'doc_type' in data: d.doc_type=str(data['doc_type'])[:80]
  DB.session.commit();audit('document.metadata',case_id=d.case_id,document_id=did);return jsonify(d.view())

 @app.post('/api/documents/<int:did>/versions')
 @guard
 def new_version(did):
  d=ensure_doc(did)
  if current_user().role not in ('administrator','investigator','legal_advisor'): abort(403)
  f=request.files.get('file')
  if not f: return jsonify(error='Select a file'),400
  if Path(secure_filename(f.filename or '')).suffix.lower()!=Path(d.name).suffix.lower(): return jsonify(error='Version must use same format'),400
  data=f.read()
  try: v=save_version(d,data)
  except ValueError as e: return jsonify(error=str(e)),400
  return jsonify(v.view()),201

 @app.get('/api/documents/<int:did>/verify')
 @guard
 def verify_document(did):
  d=ensure_doc(did);v=Version.query.filter_by(document_id=did).order_by(Version.number.desc()).first()
  try: read_version(d,v);result=dict(valid=True,sha256=v.sha256,version=v.number)
  except (InvalidTag,ValueError,OSError): result=dict(valid=False,error='Stored file failed verification')
  audit('document.verify','success' if result['valid'] else 'failed',case_id=d.case_id,document_id=did)
  return jsonify(result)

 @app.get('/api/documents/<int:did>/download')
 @guard
 @limiter.limit('80 per hour')
 def download(did):
  d=ensure_doc(did,download=True)
  number=request.args.get('version',type=int)
  q=Version.query.filter_by(document_id=did)
  v=q.filter_by(number=number).first() if number else q.order_by(Version.number.desc()).first()
  if not v: abort(404)
  try: data=read_version(d,v)
  except (InvalidTag,ValueError,OSError):
   audit('document.download','integrity_failed',case_id=d.case_id,document_id=did)
   return jsonify(error='Integrity check failed'),409
  ext=Path(d.name).suffix.lower()
  try: data=watermark(data,ext,current_user().username)
  except Exception:
   audit('document.download','watermark_failed',case_id=d.case_id,document_id=did)
   return jsonify(error='Unable to watermark document'),422
  audit('document.download',case_id=d.case_id,document_id=did)
  return send_file(io.BytesIO(data),as_attachment=True,download_name=d.name,mimetype=mimetypes.guess_type(d.name)[0] or 'application/octet-stream')

 @app.post('/api/documents/<int:did>/share')
 @guard
 def share_document(did):
  d=ensure_doc(did)
  if current_user().role not in ('administrator','investigator','legal_advisor'): abort(403)
  data=request.get_json(silent=True) or {};uid=data.get('user_id');hours=data.get('hours',24)
  u=DB.session.get(User,uid) if uid else User.query.filter_by(username=str(data.get('username','')).strip()).first()
  if not u or not u.active: return jsonify(error='Unknown or inactive user'),400
  if not can_case(d.case_id): abort(403)
  try: hours=int(hours)
  except (ValueError,TypeError): return jsonify(error='Invalid duration'),400
  if not 1<=hours<=168: return jsonify(error='Sharing duration must be 1-168 hours'),400
  s=Share(document_id=did,user_id=uid,expires_at=now()+timedelta(hours=hours),created_by=current_user().id)
  DB.session.add(s);DB.session.commit();audit('document.shared',case_id=d.case_id,document_id=did)
  return jsonify(ok=True,expires_at=iso(s.expires_at))

 @app.get('/api/audit')
 @admin_only
 def audits(): return jsonify([a.view() for a in Audit.query.order_by(Audit.id.desc()).limit(300).all()])

 @app.get('/api/audit/verify')
 @admin_only
 def audits_verify(): return jsonify(verify_audit())

 @app.get('/api/dashboard')
 @guard
 def dashboard():
  cs=Case.query.count() if current_user().role=='administrator' else Assignment.query.filter_by(user_id=current_user().id).count()
  ds=Document.query.count() if current_user().role=='administrator' else Document.query.join(Assignment,Assignment.case_id==Document.case_id).filter(Assignment.user_id==current_user().id).count()
  return jsonify(cases=cs,documents=ds,users=User.query.count() if current_user().role=='administrator' else None,versions=Version.query.count() if current_user().role=='administrator' else None)

 @app.post('/api/backups')
 @admin_only
 def backup():
  # Export SQLAlchemy tables to JSON plus encrypted bytes; no plaintext files.
  archive=BASE/'backups';archive.mkdir(exist_ok=True)
  filename=f'backup-{now().strftime("%Y%m%d-%H%M%S")}-{secrets.token_hex(3)}.zip'
  models=[User,Case,Assignment,Document,Version,Share,Audit,Backup]
  with zipfile.ZipFile(archive/filename,'w',compression=zipfile.ZIP_DEFLATED) as z:
   for model in models:
    rows=[]
    for obj in model.query.all():
     row={}
     for col in obj.__table__.columns:
      value=getattr(obj,col.name)
      if isinstance(value,bytes): value={'hex':value.hex()}
      elif isinstance(value,datetime): value=iso(value)
      row[col.name]=value
     rows.append(row)
    z.writestr(f'tables/{model.__tablename__}.json',json.dumps(rows,indent=2))
   for f in Path(app.config['STORAGE']).glob('*.enc'): z.write(f,'encrypted/'+f.name)
  DB.session.add(Backup(filename=filename,created_by=current_user().id));DB.session.commit();audit('backup.created')
  return jsonify(filename=filename,note='Encrypted file and database export; restore requires offline administrative procedure and the separate encryption key')

 with app.app_context():
  DB.create_all()
  if not User.query.first():
   name=os.environ.get('ADMIN_USERNAME','admin');password=os.environ.get('ADMIN_PASSWORD','')
   if len(password)<12: raise RuntimeError('Set ADMIN_PASSWORD to at least 12 characters in .env')
   DB.session.add(User(username=name,password_hash=PH.hash(password),role='administrator'));DB.session.commit()
 return app

if __name__=='__main__': create_app().run(port=5000,debug=False)
