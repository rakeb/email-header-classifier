# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from jsonfield import JSONField


# Create your models here.

class DomainAttributes(models.Model):
    domain_name = models.CharField(max_length=500)
    attribute_name = models.CharField(max_length=500)
    json_attribute = JSONField()


class GeoLocation(models.Model):
    ip_address = models.CharField(max_length=200)
    json_attribute = JSONField()


class EmailVerification(models.Model):
    email_address = models.CharField(max_length=500)
    json_attribute = JSONField()
