from django.shortcuts import render, redirect
from django.contrib import messages
from .models import *
import bcrypt

def form(request):
    return render(request, 'login.html')

def success(request): 
    context={
        "all_messages": Message.objects.all(),
        "user": User.objects.get(id=request.session['user_id']),
        "all_comments": Comment.objects.all(),
    }
    return render(request, 'feed.html', context)

def registered(request):

    errors = User.objects.basic_validator(request.POST)

    if len(errors)>0:
        for key, value in errors.items():
            messages.error(request, value)
        return redirect("/")

    else:
        password = request.POST['password']
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=pw_hash)

        request.session['user_id'] = user.id

        messages.error(request, "Successfully registered!")

        return redirect("/success")

def logout(request):
    request.session.flush()
    return redirect('/')

def login(request):

    user = User.objects.filter(email=request.POST['email'])

    if len(user)>0:
        logged_user = user[0]

        if bcrypt.checkpw(request.POST['password'].encode(), logged_user.password.encode()):
            request.session['user_id'] = logged_user.id
            messages.error(request, "Successfully logged in!")
            return redirect ("/success")
        
    else:
        messages.error(request, "Password and email do not match")
        return redirect("/")

def post_message(request):
    new_message = Message.objects.create(message=request.POST['message_content'], user=User.objects.get(id=request.session['user_id']))
    request.session['message_id'] = new_message.id
    new_message.save()
    return redirect('/success')

def post_comment(request): 
    new_comment = Comment.objects.create(comment=request.POST['comment'], user=User.objects.get(id=request.session['user_id']), message=Message.objects.get(id=request.session['message_id']))
    new_comment.save()
    return redirect('/success')