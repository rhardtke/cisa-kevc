from flask import Flask, escape, Response, json
import requests
import time
import datetime
import os
import csv

home_file_dir=str(os.path.expanduser("~"))+"/.cache/"
if not os.path.isdir(home_file_dir):
    try:
        os.mkdir(home_file_dir)
    except OSError:
        print("ERROR: cant create Directory "+str(home_file_dir))
        exit(1)

# kevc_file:
# Format: CVE,Vendor/Project,Product,Vulnerability Name,Date Added to Catalog,Short Description,Action,Due Date,Notes
# source: https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
kevc_file="known_exploited_vulnerabilities.csv"
kevc_url="https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

html_css="<style>body,h2 {font-family:Arial;font-size:12pt;}h2 {font-size:16pt;} table {border-collapse: collapse;}tr {color: black;background: white;border: 1px solid black;}tr_odd {color: black;background: lightgrey;border: 1px solid black;}td {border-right: 1px solid black;}</style>"
html_head="<html><head><title>Known Exploited Vulnerabilities Catalog</title>"+html_css+"</head><body>"
html_foot="</body></html>"

def checkUpdate(mode):
    try:
        x=requests.head(kevc_url)
    except requests.exceptions.RequestException as e:
        msg="WARNING: Error during update check for newer Version of "+str(kevc_file)
        if mode == "api":
            data={}
            data['status']="fail"
            data['message']=str(msg)
            ret=json.dumps(data)
        else:
            print(msg)
            print("Error Message: "+str(e))
            ret=-1
        return ret
    updatemsg="update not needed"
    ftime=0
    if os.path.isfile(home_file_dir+kevc_file):
        ftime=os.path.getctime(home_file_dir+kevc_file)

    if time.mktime(datetime.datetime.strptime(x.headers['Last-Modified'][:-4], "%a, %d %b %Y %H:%M:%S").timetuple()) > ftime:
        try:
            updatefile=requests.get(kevc_url)
        except Exception as e:
            msg="WARNING: cant load new File from URL: "+str(kevc_url)
            if mode == "api":
                data={}
                data['status']="fail"
                data['message']=str(msg)
                data['exception']=str(e)
                ret=json.dumps(data)
            else:
                print(str(msg))
                print(str(e))
                ret=-1
            return ret
        try:
            with open(str(home_file_dir+kevc_file)+".new","wb") as fp:
                fp.write(updatefile.content)
                if os.path.isfile(home_file_dir+kevc_file):
                    os.rename(home_file_dir+kevc_file,str(home_file_dir+kevc_file)+".old")
            os.rename(str(home_file_dir+kevc_file)+".new",home_file_dir+kevc_file)
        except Exception as e:
            msg="WARNING: cant write new File: "+str(kevc_file)
            if mode == "api":
                data={}
                data['status']="fail"
                data['message']=str(msg)
                data['exception']=str(e)
                ret=json.dumps(data)
            else:
                print(msg)
                print(str(e))
                ret=-1
            return ret
        updatemsg="update successfully"
    if mode == "api":
        data={}
        data['status']="ok"
        data['message']=updatemsg
        ret=json.dumps(data)
    else:
        ret=0
    return ret

def FileOpen(fname):
    try:
        fp=open(fname, "r",newline='')
        csvfp=csv.reader(fp,delimiter=',', quotechar='"')
        return csvfp
    except IOError:
        print("ERROR: no such file '"+str(fname)+"'.")
        exit(1)

def searchObject(object,rowid):
	csvfp=FileOpen(home_file_dir+kevc_file)
	found=False
	datalist=[]
	i=0
	for row in csvfp:
		if str.upper(object) in str.upper(row[rowid]) or not object:
			found=True
			data={}
			data['CVE']=row[0]
			data['Vendor']=row[1]
			data['Product']=row[2]
			data['Vulnerability']=row[3]
			data['Description']=row[5]
			data['Notes']=row[8]
			data['Fix']=row[6]
			data['Added to List']=row[4]
			data['Due Date']=row[7]
			datalist.append(data)
			i+=1
	if found is False:
            err={}
            err['total']=i
            err['status']="fail"
            err['message']=str(escape(str(object)))+" not found'"
            datalist.append(err)
	else:
		data={}
		data['total']=i
		data['status']='OK'
		datalist.append(data)
	return json.dumps(datalist)

app=Flask(__name__)
@app.route("/",methods=["GET"])
def root():
    csvfp=FileOpen(home_file_dir+kevc_file)
    HTML=html_head
    HTML+="<h2>Known Exploited Vulnerabilities Catalog from <a href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog' target=_blank>CISA</a></h2><br>\n"
    HTML+="Needed File can be downloaded at <a href='https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'>https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv</a>.<br>"
    HTML+="<br>Api is also available, see <a href='/api'>this Link for description</a><br><br>\n"
    HTML+="<table>\n"
    for row in csvfp:
        HTML+="<tr>"
        for data in row:
            HTML+="<td>"+str(data)+"</td>"
        HTML+="</tr>\n"
    HTML+="</table>\n"
    HTML+=html_foot
    return str(HTML)

@app.route("/api")
def apiText():
	data={}
	data['/api']="This Message"
	data['/api/update']="update Known Exploited Vulnerabilities Catalog"
	data['/api/list']="returns all entries"
	data['/api/cve/<CVE>']="returns details from <CVE>"
	data['/api/vendor/<vendor>']="returns list with all entries for <vendor>"
	data['/api/vendor/<product>']="returns list with all entries for <product>"
	data['status']="ok"
	return Response(json.dumps(data),mimetype='application/json')

@app.route("/api/list")
def getAll():
    json=searchObject("",0)
    return Response(json,mimetype='application/json')

@app.route("/api/cve/<id>")
def searchCVE(id):
    json=searchObject(id,0)
    return Response(json,mimetype='application/json')
	
@app.route("/api/vendor/<id>")
def searchVendor(id):
	json=searchObject(id,1)
	return Response(json,mimetype='application/json')

@app.route("/api/product/<id>")
def searchProduct(id):
    json=searchObject(id,2)
    return Response(json,mimetype='application/json')

@app.route("/api/update")
def updateFile():
    json=checkUpdate("api")
    return Response(json,mimetype='application/json')

checkUpdate("console")
if __name__ == "__main__":
    app.run(host='0.0.0.0',port=10000)
