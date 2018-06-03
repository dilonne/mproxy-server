import http.client
import re
import urllib
import json
import requests

from flask import Flask, Blueprint, request, Response, url_for, abort
from werkzeug.datastructures import Headers
from werkzeug.exceptions import NotFound

app = Flask(__name__)

# Default Configuration
DEBUG_FLAG = True
LISTEN_PORT = 7788

proxy = Blueprint('proxy', __name__)

# You can insert Authentication here.
# proxy.before_request(check_login)

# Filters.
HTML_REGEX = re.compile(r'((?:src|action|href)=["\'])/')
JQUERY_REGEX = re.compile(r'(\$\.(?:get|post)\(["\'])/')
JS_LOCATION_REGEX = re.compile(r'((?:window|document)\.location.*=.*["\'])/')
CSS_REGEX = re.compile(r'(url\(["\']?)/')

REGEXES = [HTML_REGEX, JQUERY_REGEX, JS_LOCATION_REGEX, CSS_REGEX]


def iterform(multidict):
    for key in multidict.keys():
        for value in multidict.getlist(key):
            yield (key.encode("utf8"), value.encode("utf8"))


def parse_host_port(h):
    """Parses strings in the form host[:port]"""
    host_port = h.split(":", 1)
    if len(host_port) == 1:
        return (h, 80)
    else:
        host_port[1] = int(host_port[1])
        return host_port


@proxy.route('/')
def index():
    return ""


# For RESTful Service
@proxy.route('/proxy/<host>/', methods=["GET", "POST", "PUT", "DELETE"])
@proxy.route('/proxy/<host>/<path:file>', methods=["GET", "POST", "PUT", "DELETE"])
def proxy_request(host, file=""):
    hostname, port = parse_host_port(host)

    if "proxy" in hostname:
        abort(403)

    response = requests.get("https://proxy-filter.herokuapp.com/is_blacklisted", params={'hostname': hostname})
    json_response = response.content.decode()
    response_dictionary = json.loads(json_response)

    success = response_dictionary['success']
    message = response_dictionary['message']

    if success == 0:
        abort(403)

    else:

        # Whitelist a few headers to pass on
        request_headers = {}
        for h in ["Cookie", "Referer", "X-Csrf-Token"]:
            if h in request.headers:
                request_headers[h] = request.headers[h]

        if request.query_string:
            path = "/%s?%s" % (file, request.query_string)

        else:
            path = "/" + file

        if request.method == "POST" or request.method == "PUT":
            form_data = list(iterform(request.form))
            form_data = urllib.urlencode(form_data)
            request_headers["Content-Length"] = len(form_data)
        else:
            form_data = None

        conn = http.client.HTTPConnection(hostname, port)

        conn.request(request.method, path, body=form_data, headers=request_headers)

        resp = conn.getresponse()


        # Clean up response headers for forwarding
        d = {}
        response_headers = Headers()
        for key, value in resp.getheaders():
            d[key.lower()] = value
            if key in ["content-length", "connection", "content-type"]:
                continue

            if key == "set-cookie":
                cookies = value.split(",")
                [response_headers.add(key, c) for c in cookies]
            else:
                response_headers.add(key, value)

        # If this is a redirect, munge the Location URL
        if "location" in response_headers:
            redirect = response_headers["location"]

            response = requests.get(redirect)
            return response.content

        # Rewrite URLs in the content to point to our URL schemt.method == " instead.
        # Ugly, but seems to mostly work.
        root = url_for(".proxy_request", host=host)
        contents = resp.read()

        # Restructing Contents.
        if d["content-type"].find("application/json") >= 0:
            # JSON format contents will be modified here.
            jc = json.loads(contents)
            if jc.has_key("nodes"):
                del jc["nodes"]
            contents = json.dumps(jc)

        else:
            # Generic HTTP.
            for regex in REGEXES:
                contents = regex.sub(r'\1%s' % root, contents)

        flask_response = Response(response=contents,
                                  status=resp.status,
                                  headers=response_headers,
                                  content_type=resp.getheader('content-type'))
        return flask_response.data


# app.register_blueprint(proxy)
if __name__ == '__main__':
    app.run()
