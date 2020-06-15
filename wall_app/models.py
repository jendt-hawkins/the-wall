from django.db import models
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class UserManager(models.Manager):
    def basic_validator(self, postData):

        errors = {}

        if len(postData['first_name'])<2:
            errors['first_name'] = "First name must be at least 2 characters"

        if len(postData['last_name'])<2:
            errors['last_name'] = "Last name must be at least 2 characters"

        if len(postData['email'])<1:
            errors['email'] = "Email cannot be blank"
        elif not EMAIL_REGEX.match(postData['email']):               
            errors['email'] = "Invalid email address"

        if len(postData['password'])<8:
            errors['password'] = "Password must be at least 8 characters"

        if postData['password'] != postData['confirm']:
            errors['passwords'] = "Passwords must match"

        return errors

class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    objects = UserManager()

class Message(models.Model):
    message = models.TextField()
    user = models.ForeignKey(User, related_name="messages", on_delete = models.CASCADE)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

class Comment(models.Model):
    comment = models.TextField()
    user = models.ForeignKey(User, related_name="comments_created", on_delete = models.CASCADE)
    message = models.ForeignKey(Message, related_name="has_comments", on_delete = models.CASCADE)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)