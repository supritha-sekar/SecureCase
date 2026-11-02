import os,io,hashlib,pytest
os.environ.setdefault('SECRET_KEY','test-secret-key-at-least-32-characters-long')
os.environ.setdefault('DOCUMENT_KEY','a'*64)
os.environ.setdefault('ADMIN_USERNAME','admin')
os.environ.setdefault('ADMIN_PASSWORD','test-administrator-password')
from app import create_app,DB,User,Case,Assignment,Document,Version,Audit,verify_audit,read_version

@pytest.fixture
def client(tmp_path):
 app=create_app({'TESTING':True,'SQLALCHEMY_DATABASE_URI':'sqlite:///'+str(tmp_path/'test.db'),'STORAGE':str(tmp_path/'encrypted'),'RATELIMIT_ENABLED':False})
 with app.app_context():
  yield app.test_client()

def auth(client):
 response=client.post('/api/login',json={'username':'admin','password':'test-administrator-password'})
 assert response.status_code==200,response.json
 return {'X-CSRF-Token':response.json['csrf']}

def test_login_csrf(client):
 assert client.get('/api/me').status_code==401
 assert client.post('/api/login',json={'username':'admin','password':'wrong'}).status_code==401
 headers=auth(client)
 assert client.get('/api/me').json['user']['role']=='administrator'
 assert client.post('/api/cases',json={'title':'No CSRF'}).status_code==403
 assert client.post('/api/logout',headers=headers).status_code==200
 assert client.get('/api/me').status_code==401

def test_upload_version_integrity_audit(client):
 h=auth(client)
 c=client.post('/api/cases',json={'title':'Demo case'},headers=h).json
 response=client.post(f"/api/cases/{c['id']}/documents",data={'file':(io.BytesIO(b'%PDF-1.4\n%%EOF'), 'sample.pdf'),'doc_type':'FIR'},headers=h)
 assert response.status_code==201,response.json
 d=response.json
 assert d['current_version']==1
 assert client.get(f"/api/documents/{d['id']}/verify").json['valid']
 response=client.post(f"/api/documents/{d['id']}/versions",data={'file':(io.BytesIO(b'%PDF-1.4\nsecond\n%%EOF'),'sample.pdf')},headers=h)
 assert response.status_code==201,response.json
 assert response.json['number']==2
 with client.application.app_context():
  doc=DB.session.get(Document,d['id']);v=Version.query.filter_by(document_id=d['id'],number=1).first()
  assert read_version(doc,v)==b'%PDF-1.4\n%%EOF'
  assert verify_audit()['valid']
  a=Audit.query.first();a.action='tampered';DB.session.commit()
  assert not verify_audit()['valid']

def test_case_permissions(client):
 h=auth(client)
 case=client.post('/api/cases',json={'title':'Secret'},headers=h).json
 user=client.post('/api/users',json={'username':'clerk1','password':'a secure password 123','role':'clerk'},headers=h).json
 assert user['role']=='clerk'
 client.post('/api/logout',headers=h)
 clerk=client.post('/api/login',json={'username':'clerk1','password':'a secure password 123'})
 h={'X-CSRF-Token':clerk.json['csrf']}
 assert client.get('/api/cases').json==[]
 assert client.get('/api/documents?case_id='+str(case['id'])).json==[]
 assert client.post('/api/cases',json={'title':'No'},headers=h).status_code==403
 assert client.post(f"/api/cases/{case['id']}/documents",data={'file':(io.BytesIO(b'hello'),'x.txt')},headers=h).status_code==403
