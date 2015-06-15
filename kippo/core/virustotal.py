import urllib
import urllib2
import simplejson
import postfile
import virustotal_backlogs

def get_report(apikey, resource, filename, dl_url='unknown', honeypot=None, origin=None):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": resource,
                  "apikey":   apikey }
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    j = simplejson.loads(json)

    if j['response_code'] == 1: # file known
        msg = 'Virustotal report of %s [%s] at %s' % \
            (resource, dl_url, j['permalink'])
        # we need to print msg, because logs from SFTP are dispatched this way
        print msg
        if honeypot:
            honeypot.logDispatch(msg)

        msg = 'virustotalscan %s in %s' % \
            (resource, json)
        if honeypot:
            honeypot.logDispatch(msg)
        else:
            # we need to print msg, because logs from SFTP are dispatched this way
            print msg
    elif j['response_code'] == 0: # file not known
        if origin == 'db':
            return j['response_code']

        msg = 'Virustotal not known, response code: %s' % (j['response_code'])
        print msg
        host = "www.virustotal.com"
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", apikey)]
        filepath = "dl/%s" % resource
        file_to_send = open(filepath, "rb").read()
        files = [("file", filename, file_to_send)]
        json = postfile.post_multipart(host, url, fields, files)
        print json

        msg = 'insert to Virustotal backlog %s [%s]' % \
            (resource, dl_url)
        print msg
        virustotal_backlogs.insert(resource, dl_url)
    else:
        msg = 'Virustotal not known, response code: %s' % (j['response_code'])
        print msg
    return j['response_code']

def make_comment(apikey, resource):
    url = "https://www.virustotal.com/vtapi/v2/comments/put"
    parameters = {"resource": resource,
                   "comment": "captured by ssh honeypot",
                   "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    print json
