import json

from twisted.web import resource

from tint.log import Logger
from tint.storage.permanent import TintURI
from tint.ssl.keymagic import PublicKey

log = Logger(system="TintWebAPI")


class WebAPI(resource.Resource):
    def __init__(self, peerServer):
        resource.Resource.__init__(self)
        self.putChild('v1', APIVersionOne(peerServer))


class APIVersionOne(resource.Resource):
    def __init__(self, peerServer):
        resource.Resource.__init__(self)
        self.putChild('storage', StorageResource(peerServer))
        self.putChild('keys', KeysResource(peerServer))
        self.putChild('permissions', PermissionsResource(peerServer))


class Request(object):
    def __init__(self, req):
        self.req = req
        self.pathparts = req.path.split("/")

    def getParam(self, name, default=None):
        return self.req.args.get(name, [default])[0]

    def setType(self, ctype):
        self.req.setHeader('content-type', ctype)

    def json(self, obj):
        if self.req._disconnected:
            return
        self.setType("application/json")
        return json.dumps(obj)

    def success(self, data=None):
        r = { 'success': True }
        r.update(data or {})
        return self.json(r)

    def failure(self, reason):
        r = { 'success': False, 'reason': str(reason) }
        return self.json(r)


class KeysResource(resource.Resource):
    def __init__(self, peerServer):
        resource.Resource.__init__(self)
        self.peerServer = peerServer

    def render_GET(self, req):
        req = Request(req)
        keys = []
        for key in self.peerServer.keyStore.getAuthorizedKeysList():
            keys.append({ 'id': key.getKeyId(), 'key': str(key) })
        data = { 'mykey':
                 { 'id': self.peerServer.getKeyId(),
                   'key': str(self.peerServer.getPublicKey()) },
                 'authorized_keys': keys }
        return req.success(data)

    def render_POST(self, req):
        req = Request(req)
        key = req.getParam('key')
        name = req.getParam('name')
        try:
            publicKey = PublicKey(key)
            self.peerServer.keyStore.setAuthorizedKey(publicKey, name)
            return req.success()
        except Exception, err:
            return req.failure(err)


class StorageResource(resource.Resource):
    def __init__(self, peerServer):
        resource.Resource.__init__(self)
        self.peerServer = peerServer
        self.myId = self.peerServer.getKeyId()

    def getChild(self, path, request):
        return self

    def getKeyURI(self, req):
        uri = "tint://%s" % "/".join(req.pathparts[4:])
        return TintURI(uri)

    def render_GET(self, req):
        req = Request(req)
        uri = self.getKeyURI(req)
        value = self.peerServer.get(uri.host, uri.path)
        if value is None:
            return req.failure("Key not found")
        return req.success({ 'value': value })

    def render_PUT(self, req):
        req = Request(req)
        amount = req.getParam('amount', 1)
        default = req.getParam('default', 0)
        uri = self.getKeyURI(req)
        try:
            self.peerServer.incr(uri.host, uri.path, amount, default)
            return req.success()
        except Exception, err:
            return req.failure(err)

    def render_POST(self, req):
        req = Request(req)
        data = req.getParam('data', "")
        uri = self.getKeyURI(req)
        try:
            self.peerServer.set(uri.host, uri.path, data)
            return req.success()
        except Exception, err:
            return req.failure(err)


class PermissionsResource(resource.Resource):
    def __init__(self, peerServer):
        resource.Resource.__init__(self)
        self.peerServer = peerServer

    def getChild(self, path, request):
        return self

    def render_GET(self, req):
        req = Request(req)
        authorizedUser = req.pathparts[4]
        permission = '/'.join(req.pathparts[5:])

        # TODO: check that authorizedUser is in the list of authorizedKeys

        try:
            self.peerServer.storage.testAccess(authorizedUser, permission)
            return req.success()
        except Exception, err:
            return req.failure(err)

    def render_POST(self, req):
        req = Request(req)
        authorizedUser = req.pathparts[4]
        permission = '/'.join(req.pathparts[5:])

        # TODO: check that authorizedUser is in the list of authorizedKeys

        try:
            self.peerServer.storage.grantAccess(authorizedUser, permission)
            return req.success()
        except Exception, err:
            return req.failure(err)
