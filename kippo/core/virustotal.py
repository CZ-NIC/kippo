import urllib
import urllib2
import simplejson
import postfile

def get_report(apikey, resource, dl_url='unknown', honeypot=None):
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
