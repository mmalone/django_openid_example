import openid.store
import time
from django.db import models
from django.db.models import F
from django.conf import settings
from openid.store.interface import OpenIDStore
from openid.association import Association as OIDAssociation

class Nonce(models.Model):
    server_url = models.CharField(max_length=255)
    timestamp = models.IntegerField()
    salt = models.CharField(max_length=40)

    def __unicode__(self):
        return u"Nonce: %s for %s" % (self.salt, self.server_url)


class Association(models.Model):
    server_url = models.TextField(max_length=2047)
    handle = models.CharField(max_length=255)
    secret = models.CharField(max_length=255)
    issued = models.IntegerField()
    lifetime = models.IntegerField()
    type = models.CharField(max_length=64)

    def __unicode__(self):
        return u'Association: %s, %s' % (self.server_url, self.handle)


class DjangoOpenIDStore(OpenIDStore):
    """
    An OpenID store subclass that persists data using the Django ORM.
    """

    def storeAssociation(self, server_url, association):
        Association.objects.create(
            server_url = server_url,
            handle = association.handle,
            secret = association.secret.encode('base64'),
            issued = association.issued,
            lifetime = association.issued,
            type = association.assoc_type
        )

    def getAssociation(self, server_url, handle=None):
        associations = Association.objects.filter(server_url=server_url)
        if handle is not None:
            associations = associations.filter(handle=handle)
        if not associations:
            return None
        oid_associations = []
        for association in associations:
            association = OIDAssociation( 
                association.handle, 
                association.secret.decode('base64'),
                association.issued, 
                association.lifetime, 
                association.type
            )
            if association.getExpiresIn() == 0:
                self.removeAssociation((association.issued, association.handle))
            else:
                oid_associations.append(association)
        if not oid_associations:
            return None
        return oid_associations[-1]

    def removeAssociation(self, server_url, handle):
        associations = Association.objects.filter(server_url=server_url, handle=handle)
        try:
            return bool(list(associations))
        finally:
            associations.delete()

    def useNonce(self, server_url, timestamp, salt):
        if abs(timestamp - time.time()) > openid.store.nonce.SKEW:
            return False
        nonce, created = Nonce.objects.get_or_create(
            server_url=server_url,
            timestamp=timestamp,
            salt=salt
        )
        return created

    def cleanupNonce(self):
        Nonce.objects.filter(timestamp__lt=int(time.time()) - openid.store.nonce.SKEW).delete()

    def cleanupAssociations(self):
        Association.objects.filter(issued__lt=int(time.time()) + F('lifetime')).delete()

    def getAuthKey(self):
        return md5.new(settings.SECRET_KEY).hexdigest()[:self.AUTH_KEY_LEN]

    def isDumb(self):
        return False
