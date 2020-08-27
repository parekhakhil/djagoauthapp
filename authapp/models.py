'''from django.db import models
from django.contrib.auth.models import  User
from django.urls import reverse
from django.db.models.signals import post_save
from django.dispatch import receiver
from smartfields import fields
from smartfields.dependencies import FileDependency
from smartfields.processors import ImageProcessor
import uuid
import os

# Create your models here.

def rename_path_and_avatar(path):
        def wrapper(instance,filename):
            #avatar = filename.split('.')[0]
            ext = filename.split('.')[-1]
            if instance.pk:
                avatar_id = 'uid_%s'%(instance.pk)
                avatar_name = '%s_%s'%(instance.user.first_name, instance.user.last_name)
                filename = '{}_{}_{}.{}'.format(avatar_id,avatar_name,uuid.uuid4().hex,ext)
            else:
                random_id = 'r_id%s'%(uuid.uuid4().hex)
                filename = '{}_{}'.format(random_id,filename)
            return os.path.join(path,filename)
        return wrapper
avatar_image_upload_path = rename_path_and_avatar('user_avatar/')
# assign it `__qualname__`
avatar_image_upload_path.__qualname__ = 'avatar_image_upload_path'


class Profile(models.Model):
    user = models.OneToOneField(User,related_name='profile',on_delete=models.CASCADE)
    avatar = fields.ImageField(upload_to=avatar_image_upload_path,blank=True,default = 'static/user-bg.jpg', dependencies=[
        FileDependency( processor=ImageProcessor(
            format='JPEG', scale={'max_width': 150, 'max_height': 150})),
    ])
    about = models.TextField(blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
'''