from celery import Celery
from time import sleep
import requests,json

celery = Celery('tasks', broker='redis://localhost:6379/0')
SQLMAPAPI_URL="http://127.0.0.1:9999"
TASK_NEW_URL=SQLMAPAPI_URL+"/task/new"
@celery.task
def add(url,cookie,referer):
	task_new=requests.get(TASK_NEW_URL)
	task_id=task_new.json()["taskid"]
	requests.post(SQLMAPAPI_URL+"/scan/"+task_id+"/start",data=json.dumps({'url':url,"cookie":cookie,"referer":referer,"data":"a=i&sql=root&x=y"}),headers={"content-type":"application/json"})
	task_status=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/status")
	count=1
	while(task_status.json()["status"]!="terminated"):
		task_status=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/status")
		sleep(count)
		count=count*2
	task_result=requests.get(SQLMAPAPI_URL+"/scan/"+task_id+"/data")
	return task_result.json()
#print add("http://contentrecommend-out.mobile.sina.cn/interface/pcright/pcright_topic.php?posid=pos520c8516722cb&psid=PDPS000000051603&wbVersion=v6&uid=2699581760&ip=106.39.10.162&cursor=18&eData=12.33,6&callback=wbad_14381098441337&rnd=14381505350298")
print add("http://127.0.0.1/sql.php?sql=root",cookie="a=222;b=1",referer="a")
