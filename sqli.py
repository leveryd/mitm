#coding:utf-8
import time
import re
from libmproxy.flow import FlowWriter
from libmproxy.script import concurrent
import requests,json
import base64
#from libmproxy.protocol.http import decoded
#DEBUG2打印已有URL LIST
#DEBUG1打印调试信息
DEBUG="DEBUG3"
SQLI_FOUND_URLS=[]
SQLI_POST_HAVE_CHECKED_URLS=[]
SQLI_GET_HAVE_CHECKED_URLS=[]
######options check which######
ENABLE_SSRF=1
def url_exclude(url):
	filter_keywords=["js","css","gif","jpeg","png","swf","jpg","ico","http://www.google-analytics.com","http://192.168.0.1","xsxsxrxf=1","xcxsxrxf=1","http://pagead2.googlesyndication.com","http://googleads.g.doubleclick.net","http://pos.baidu.com","http://z8.cnzz.com/stat.htm","google.com.hk","xcxsxrxf=1","http://api.share.baidu.com"]
	for keyword in filter_keywords:
		if url.find(keyword)!=-1:
			return 1
	return 0
def url_include(url):
	filter_keywords=[]
	for keyword in filter_keywords:
		if url.find(keyword)==-1:
			return 1
	return 0
def d_print(msg,level=1):
    	if DEBUG=="DEBUG"+str(level):
		print msg
def p(keywords,content):
	for keyword in keywords:
		if keyword in content.lower():
			return 1
    	return 0
def p_re(keywords,content):
	for keyword in keywords:
		d_print(keyword+"  "+content)
		r=re.findall(keyword,content.lower())
		if len(r)>0:
			return r[0]
	return 0
def url_include_site(values):
	for value in values:
		r=p_re(["(http://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})","(http://)?([\s\S]{1,}\.cn)","(http://)?([\s\S]{1,}\.com)","(http://)?([\s\S]{1,}\.tk)","(http://)?([\s\S]{1,}\.so)","(http://)?([\s\S]{1,}\.net)","(http://)?([\s\S]{1,}\.org)"],value)
		if r:
			return r[1]
	return 0
#determine if url parameters contains filename
def php_file_include(values):
	for value in values:
		if p_re(["[\d\w-]{1,}\.php","[\d\w-]{1,}\.asp","[\d\w-]{1,}\.jsp","[\d\w-]{1,}\.do","[\d\w-]{1,}\.action","[\d\w-]{1,}\.htm"],value):
			return 1
	return 0
#determine if url parameters contains filename
def file_include(values):
	for value in values:
		if p_re(["[\d\w-]{1,}\.htm","[\d\w-]{1,}\.php","[\d\w-]{1,}\.asp","[\d\w-]{1,}\.jsp","[\d\w-]{1,}\.do","[\d\w-]{1,}\.action","[\d\w-]{1,}\.txt","[\d\w-]{1,}\.xls","[\d\w-]{1,}\.doc","[\d\w-]{1,}\.xml"],value):
			return 1
	return 0
def get_values(xxdict):
	yydict=[]
	for xx in xxdict:
		yydict.append(xx[1])
	return yydict
def chongfu(request,listname):
	base_url=request.url.split("?")[0]
	names=request.get_query().keys()
        names.sort()
	#determine tow similar url
	#such as a.com/a.php?file=a.html and a.com/a.php?file=b.html
	if base_url+str(names) not in listname:
		return 1
	return 0
	
def output(listname,request,loudongming,context):
	base_url=request.url.split("?")[0]
	names=request.get_query().keys()
        names.sort()
	#determine tow similar url
	#such as a.com/a.php?file=a.html and a.com/a.php?file=b.html
	if chongfu(request,listname):
		print("----"+loudongming+" Found-----\n"+request.method+" "+request.url)
		listname.append(base_url+str(names))
	if loudongming=="XXE":
		print request.headers
		print request.content
	d_print(listname,2)
def keys(request):
	return request.get_query().keys()
				
@concurrent
def request(context, flow):
	request=flow.request
	#use request.url,not request.host
        #because http://anysice.google.com/xxx.php?url=http://test.com/aa
	if url_exclude(request.url)==0 and url_include(request.host)==0:
		#if f.request.method=="GET":
		#	f.request.headers['cookie']={'cookie=testfortest'}
		#	context.replay_request(f,block=True)
		values=get_values(request.get_query().items())
		r=url_include_site(values)
		if ENABLE_SQLI: 
			#GET request,may not send request to php,asp,jsp,so we need to determine
			#POST request,it must be sent to a web server script
			#判断GET请求是否有参数，没参数就不要浪费sqlmapapi时间了
			if request.method=="GET" and chongfu(request,SQLI_GET_HAVE_CHECKED_URLS) and php_file_include(request.get_path_components()) and len(keys(request))>0:
				#print request.headers
				#print type(request.headers)
				#add this url to SQLI_GET_HAVE_HECEKD_URLS
				names=request.get_query().keys()
				names.sort()
				#SQLI_GET_HAVE_CHECKED_URLS.append(request.url.split("?")[0]+str(names))
				#print SQLI_GET_HAVE_CHECKED_URLS
				#send to celery
				cookie=""
				referer=""
				if len(request.headers['cookie'])>0:
					cookie=request.headers['cookie'][0]
				if len(request.headers['referer'])>0:
					referer=request.headers['referer'][0]
				args = {'args': [request.url,base64.encodestring(cookie),referer,"mitm-test-for-get"]}
				#resp = requests.post("http://localhost:5555/api/task/async-apply/tasks.sqlmap_dispath", data=json.dumps(args))
				resp = requests.post("http://203.195.211.242:9000/api/task/async-apply/tasks.sqlmap_dispath", data=json.dumps(args))
				#resp = tasks.sqlmap_dispath.delay(request.url,cookie,referer,"mitm-test-for-get")
				#print "push ",resp
			if request.method=="POST" and chongfu(request,SQLI_POST_HAVE_CHECKED_URLS):
				#add this to SQLI_POST_HAVE_CHECKED_URLS
				names=request.get_query().keys()
				names.sort()
				SQLI_POST_HAVE_CHECKED_URLS.append(request.url.split("?")[0]+str(names))
				cookie=""
				referer=""
				if len(request.headers['cookie'])>0:
					cookie=request.headers['cookie'][0]
				if len(request.headers['referer'])>0:
					referer=request.headers['referer'][0]
				data=request.content
				args = {'args': [request.url,base64.encodestring(cookie),referer,base64.encodestring(data)]}
				#resp = requests.post("http://localhost:5555/api/task/async-apply/tasks.sqlmap_dispath", data=json.dumps(args))
				resp = requests.post("http://203.195.211.242:9000/api/task/async-apply/tasks.sqlmap_dispath", data=json.dumps(args))
				#resp = tasks.sqlmap_dispath.delay(request.url,cookie,referer,data)
				#print "push ",resp
			
