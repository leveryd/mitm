#coding:utf-8
from celery import Celery,platforms
from time import sleep
import requests,json
import MySQLdb
import base64
import subprocess

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

@app.task
def subbrute_dispath(targets):
        # 命令执行环境参数配置
        import os
        run_script_path = os.getcwd()+"/subDomainsBrute/"
        #run_env = '{"LD_LIBRARY_PATH": "/home/ubuntu/thorns/libs/"}'

        cmdline = 'python  '+run_script_path+'subDomainsBrute.py %s' % (targets)

        subbrute_proc = subprocess.Popen(cmdline,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=run_script_path)

        process_output = subbrute_proc.stdout.readlines()
        return process_output
#print add("http://contentrecommend-out.mobile.sina.cn/interface/pcright/pcright_topic.php?posid=pos520c8516722cb&psid=PDPS000000051603&wbVersion=v6&uid=2699581760&ip=106.39.10.162&cursor=18&eData=12.33,6&callback=wbad_14381098441337&rnd=14381505350298")
