# coding=utf-8
from django import  template
import datetime
register=template.Library()
@register.filter(name='split')
def split(value, arg):
    return value.split(arg)
@register.filter(name='get')
def get(value, arg):
    return value[int(arg)]