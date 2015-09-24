#coding:utf-8
from celery import Celery,platforms
from time import sleep
import requests,json
import MySQLdb

SQLMAPAPI_URL="http://127.0.0.1:9999"
TASK_NEW_URL=SQLMAPAPI_URL+"/task/new"
app = Celery()
platforms.C_FORCE_ROOT = True


app.conf.update(
        CELERY_IMPORTS = ("tasks", ),
        BROKER_URL = 'redis://203.195.211.242:8090/0',
        #BROKER_URL = 'redis://127.0.0.1:6379/0',
        #CELERY_RESULT_BACKEND = 'db+mysql://root:exp123@127.0.0.1:3306/test',
        CELERY_TASK_SERIALIZER='json',
        CELERY_RESULT_SERIALIZER='json',
        CELERY_TIMEZONE='Asia/Shanghai',
        CELERY_ENABLE_UTC=True,
        CELERY_REDIS_MAX_CONNECTIONS=5000, 
)

class Database:
    host = '203.195.211.242'
    user = 'sqlmap'
    password = 'sqlmapx123'
    port=8010
    #host = '127.0.0.1'
    #user = 'root'
    #password = 'exp123'
    db = 'sqlmap'
    charset = 'utf8'

    def __init__(self):
        self.connection = MySQLdb.connect(host=self.host,port=self.port,user=self.user,passwd=self.password,db=self.db,charset=self.charset)
        self.cursor = self.connection.cursor()

    def insert(self, query):
        try:
            self.cursor.execute(query)
            self.connection.commit()
        except:
            self.connection.rollback()

    def query(self, query):
        cursor = self.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(query)
        return cursor.fetchall()

    def __del__(self):
        self.connection.close()

@app.task
def sqlmap_dispath(url,cookie,referer,data):
	task_new=requests.get(TASK_NEW_URL)
	task_id=task_new.json()["taskid"]
	cookie=base64.decodestring(cookie)
	if data!="mitm-for-test":
		data=base64.decodestring(data)
	if data!="mitm-for-test":
		requests.post(SQLMAPAPI_URL+"/scan/"+task_id+"/start",data=json.dumps({'url':url,"cookie":cookie,"referer":referer,"data":data}),headers={"content-type":"application/json"})
	else:
		requests.post(SQLMAPAPI_URL+"/scan/"+task_id+"/start",data=json.dumps({'url':url,"cookie":cookie,"referer":referer}),headers={"content-type":"application/json"})
	task_status=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/status")
	count=1
	while(task_status.json()["status"]!="terminated"):
		task_status=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/status")
		sleep(count)
		count=count*2
	task_result=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/data")
	print task_result.json()
	#存在注入,存进数据库中
	if task_result.json()['data']!="[]":
		mysql=Database()
		mysql.insert("insert into sqlmap_result(taskid,result,url,cookie,referer,data) values('%s','%s','%s','%s','%s','%s')"%("NULL",task_result.json()['data'],url,cookie,referer,data))
		return task_result.json()['data']
	#不存在注入，将这条记录删除
	else:
		return "nothing"

#print add("http://contentrecommend-out.mobile.sina.cn/interface/pcright/pcright_topic.php?posid=pos520c8516722cb&psid=PDPS000000051603&wbVersion=v6&uid=2699581760&ip=106.39.10.162&cursor=18&eData=12.33,6&callback=wbad_14381098441337&rnd=14381505350298")
