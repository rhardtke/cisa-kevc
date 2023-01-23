import time
import datetime
import os
import requests
from flask import Flask, escape, Response, json

home_file_dir=str(os.path.expanduser("~"))+"/.cache/"
if not os.path.isdir(home_file_dir):
    try:
        os.mkdir(home_file_dir)
    except OSError:
        print(f"ERROR: cant create Directory '{home_file_dir}'")
        exit(1)

# kevc_file:
# Format: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
# source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
kevc_file="known_exploited_vulnerabilities.json"
kevc_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

html_css="<style>body,h2 {font-family:Arial;font-size:12pt;}h2 {font-size:16pt;} table {border-collapse: collapse;}tr {color: black;background: white;border: 1px solid black;}tr_odd {color: black;background: lightgrey;border: 1px solid black;}td {border-right: 1px solid black;}</style>"
html_head=f"<html><head><title>Known Exploited Vulnerabilities Catalog</title>{html_css}</head><body>"
html_foot="</body></html>"

def errorMsg(msg,reqtype,status):
    if reqtype == "api":
        data={}
        if status:
            data['status']="OK"
        else:
            data['status']="FAIL"
        data['message']=str(msg)
        ret=data
    else:
        print(msg)
        if status:
            ret=0
        else:
            ret=-1
    return ret

def checkUpdate(mode):
    try:
        x=requests.head(kevc_url)
    except requests.exceptions.RequestException as e:
        ret=errorMsg(f"WARNING: Error during update check for newer Version, error code: {e}",mode,False)
        return ret
    if not x.ok:
        ret=errorMsg(f"ERROR: Error during update check for newer Version, error code: {x.status_code}",mode,False)
        return ret
    updatemsg="update not needed"
    ftime=0
    if os.path.isfile(home_file_dir+kevc_file):
        ftime=os.path.getctime(home_file_dir+kevc_file)
    if time.mktime(datetime.datetime.strptime(x.headers['Last-Modified'][:-4], "%a, %d %b %Y %H:%M:%S").timetuple()) > ftime:
        try:
            updatefile=requests.get(kevc_url)
        except Exception as e:
            ret=errorMsg(f"WARNING: cant load new File from '{kevc_url}', error code: {e}",mode,False)
            return ret
        try:
            with open(str(home_file_dir+kevc_file)+".new","wb") as fp:
                fp.write(updatefile.content)
                if os.path.isfile(home_file_dir+kevc_file):
                    os.rename(home_file_dir+kevc_file,str(home_file_dir+kevc_file)+".old")
            os.rename(str(home_file_dir+kevc_file)+".new",home_file_dir+kevc_file)
        except Exception as e:
            ret=errorMsg(f"WARNING: cant write new File: '{kevc_file}', error code: {e}'",mode,False)
            return ret
        updatemsg="update successfully"
    ret=errorMsg(updatemsg,mode,True)
    return ret

def FileOpen(fname,mode):
    try:
        fp=open(fname, "r")
        return json.load(fp)
    except IOError:
        return errorMsg(f"ERROR: no such file '{fname}'.",mode,False)

def searchObject(object,jsonfilter) -> dict:
    entries=FileOpen(home_file_dir+kevc_file,"api")
    if not "vulnerabilities" in entries:
        return entries
    datalist=[]
    for entry in entries['vulnerabilities']:
        data={}
        data['cve']=entry['cveID']
        data['vendor']=entry['vendorProject']
        data['product']=entry['product']
        data['vulnerability']=entry['vulnerabilityName']
        data['description']=entry['shortDescription']
        data['fix']=entry['requiredAction']
        data['dateAdded']=entry['dateAdded']
        data['dueDate']=entry['dueDate']
        data['notes']=entry['notes']
        if not jsonfilter and not object:
            datalist.append(data)
        else:
            if str.upper(object) in str.upper(entry[jsonfilter]):
                datalist.append(data)

    data={}
    if not datalist:
        data['message']=str(escape(str(object)))+" not found'"
    data['total']=len(datalist)
    data['status']="OK"
    data['results']=datalist
    return data

def information() -> dict:
    entries=FileOpen(home_file_dir+kevc_file,"api")
    if not "vulnerabilities" in entries:
        return entries
    datalist={ 
        'catalogVersion': entries['catalogVersion'],
        'dateReleased': entries['dateReleased'],
        'total': entries['count'],
        'status': 'OK' 
        }
    return datalist

app=Flask(__name__)
@app.route("/",methods=["GET"])
def root():
    entries=FileOpen(home_file_dir+kevc_file,"api")
    HTML=html_head
    HTML+="<h2>Known Exploited Vulnerabilities Catalog from <a href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog' target=_blank>CISA</a></h2><br>\n"
    HTML+=f"Needed File can be downloaded at <a href='{kevc_url}'>{kevc_url}</a>.<br>"
    HTML+="<br>Api is also available, see <a href='/api'>this Link for description</a><br><br>\n"
    HTML+="<table>\n"
    HTML+="<tr><td>CVE</td><td>Vendor</td><td>Product</td><td>Vulnerability</td><td>Description</td><td>Action</td><td>date Added</td><td>due Date</td></tr>\n"
    if not "vulnerabilities" in entries:
        HTML+="</table>\n"
        HTML+=f"<div id='error'>{entries['message']}</div>\n"
    else:
        for entry in entries['vulnerabilities']:
            HTML+="<tr>"
            HTML+="<td>"+str(entry['cveID'])+"</td>"
            HTML+="<td>"+str(entry['vendorProject'])+"</td>"
            HTML+="<td>"+str(entry['product'])+"</td>"
            HTML+="<td>"+str(entry['vulnerabilityName'])+"</td>"
            HTML+="<td>"+str(entry['shortDescription'])+"</td>"
            HTML+="<td>"+str(entry['requiredAction'])+"</td>"
            HTML+="<td>"+str(entry['dateAdded'])+"</td>"
            HTML+="<td>"+str(entry['dueDate'])+"</td>"
            HTML+="</tr>\n"
        HTML+="</table>\n"
    HTML+=html_foot
    return str(HTML)

@app.route("/api")
def apiText():
    data={}
    data['/api']="This Message"
    data['/api/info']="Information about Catalog"
    data['/api/update']="update Known Exploited Vulnerabilities Catalog"
    data['/api/list']="returns all entries"
    data['/api/cve/<CVE>']="returns details from <CVE>"
    data['/api/description/<search>']="returns list with all entries for <search> in 'shortDescription'"
    data['/api/vendor/<vendor>']="returns list with all entries for <vendor> in 'vendorProject"
    data['/api/product/<product>']="returns list with all entries for <product> in 'product'"
    data['status']="OK"
    return Response(json.dumps(data),mimetype='application/json')

@app.route("/api/info")
def info():
    ret=information()
    retCode=200
    if 'total' in ret:
        if ret['total'] == 0:
            retCode=404
    elif ret['status'] != "OK":
        retCode=500
    return Response(json.dumps(ret),mimetype='application/json',status=retCode)

@app.route("/api/list")
def getAll():
    ret=ret=searchObject('','')
    retCode=200
    if 'total' in ret:
        if ret['total'] == 0:
            retCode=404
    elif ret['status'] != "OK":
        retCode=500
    return Response(json.dumps(ret),mimetype='application/json',status=retCode)

@app.route("/api/cve/<id>")
def searchCVE(id):
    ret=searchObject(id,'cveID')
    retCode=200
    if 'total' in ret:
        if ret['total'] == 0:
            retCode=404
    elif ret['status'] != "OK":
        retCode=500
    return Response(json.dumps(ret),mimetype='application/json',status=retCode)

@app.route("/api/vendor/<id>")
def searchVendor(id):
    ret=searchObject(id,'vendorProject')
    retCode=200
    if 'total' in ret:
        if ret['total'] == 0:
            retCode=404
    elif ret['status'] != "OK":
        retCode=500
    return Response(json.dumps(ret),mimetype='application/json',status=retCode)

@app.route("/api/product/<id>")
def searchProduct(id):
    ret=searchObject(id,'product')
    retCode=200
    if 'total' in ret:
        if ret['total'] == 0:
            retCode=404
    elif ret['status'] != "OK":
        retCode=500
    return Response(json.dumps(ret),mimetype='application/json',status=retCode)

@app.route("/api/update")
def updateFile():
    ret=checkUpdate("api")
    retCode=200
    if ret['status'] != "OK":
        retCode=500
    return Response(json.dumps(ret),mimetype='application/json',status=retCode)

checkUpdate("console")
if __name__ == "__main__":
    app.run(host='0.0.0.0',port=10000)
